! bench_common.f90 -- shared scaffolding for the Fortran binding's
! Easy Mode bench binaries.
!
! Mirrors the cross-binding bench harness pattern: each bench case
! runs a one-iteration warm-up, then keeps doubling the iteration
! count until the measured wall-clock duration crosses a per-case
! budget (default 5 seconds, env-overridable via ITB_BENCH_MIN_SEC).
! The final batch's total wall-clock divided by its iteration count
! yields the canonical ns/op figure; payload_bytes / ns_per_op feeds
! the MB/s column.
!
! Environment variables:
!
!   ITB_NONCE_BITS    process-wide nonce width override; valid values
!                     128 / 256 / 512. Maps to itb_set_nonce_bits
!                     before any encryptor is constructed. Default 128.
!   ITB_LOCKBATCH     non-empty / non-`0` enables Lock Batch (the
!                     performance Lock Soup mode); set with ITB_LOCKSEED.
!                     Every Easy Mode encryptor additionally calls
!                     `e%set_lock_batch(1)`. Inert unless Lock Soup is
!                     engaged via ITB_LOCKSEED. Default off.
!   ITB_LOCKSEED      when set to a non-empty / non-`0` value, every
!                     Easy Mode encryptor in this run calls
!                     `e%set_lock_seed(1)`. Easy Mode auto-couples
!                     BitSoup + LockSoup as a side effect; no separate
!                     flags needed. Default off.
!   ITB_BENCH_FILTER  substring filter on bench-case names; only cases
!                     whose name contains the filter run. Default unset.
!   ITB_BENCH_MIN_SEC minimum measured wall-clock seconds per case.
!                     Default 5.0 -- wide enough to absorb the cold-
!                     cache / warm-up transient that distorts shorter
!                     measurement windows on the 16 MiB encrypt /
!                     decrypt path.
!
! Worker count defaults to `itb_set_max_workers(0)` (auto-detect),
! matching the Go bench default. Each bench main calls it before the
! first encryptor is constructed.
!
! Timing uses Fortran's intrinsic `system_clock` with a 64-bit count
! kind; the resulting counter advances at `count_rate` ticks per
! second (typically 10^9 on modern Linux). All computation is in
! double precision; throughput is reported with one decimal place
! ns/op + two decimal places MB/s.

module bench_common
  use, intrinsic :: iso_fortran_env, only: int64, real64, output_unit, error_unit
  implicit none
  private

  public :: PAYLOAD_16MB
  public :: PRIMITIVES_CANONICAL
  public :: PRIMITIVES_CANONICAL_LEN

  public :: env_nonce_bits
  public :: env_lock_batch
  public :: env_lock_seed
  public :: env_filter
  public :: env_min_seconds

  public :: random_bytes

  public :: bench_case_t
  public :: bench_run_iface
  public :: run_all
  public :: measure_one
  public :: contains_substr

  ! Default 16 MiB CSPRNG-filled payload, matching the Go bench /
  ! Python bench / Rust bench / D bench / C bench surfaces.
  integer(int64), parameter :: PAYLOAD_16MB = 16_int64 * 1024_int64 * 1024_int64

  ! Canonical PRF-grade primitive order. Mirrored verbatim across
  ! every binding's bench harness so cross-language diff comparisons
  ! align row-for-row. The three below-spec lab primitives (CRC128,
  ! FNV-1a, MD5) are not exposed through the libitb registry and are
  ! absent here by construction.
  integer, parameter :: PRIMITIVES_CANONICAL_LEN = 9
  character(len=10), parameter :: PRIMITIVES_CANONICAL(PRIMITIVES_CANONICAL_LEN) = &
      [character(len=10) :: "areion256",  "areion512",  "blake2b256", &
                            "blake2b512", "blake2s",    "blake3",     &
                            "aescmac",    "siphash24",  "chacha20"]

  ! Per-iter callable abstract interface. Each concrete bench case
  ! supplies an implementation that runs its inner encrypt / decrypt
  ! body `iters` times against a per-case context module-level state.
  abstract interface
    subroutine bench_run_iface(case_idx, iters)
      use, intrinsic :: iso_fortran_env, only: int64
      integer,        intent(in) :: case_idx
      integer(int64), intent(in) :: iters
    end subroutine
  end interface

  ! One bench case: name + per-iter callable index + payload byte
  ! count (used for the MB/s column). The harness measures wall-clock
  ! time around `run` outside the per-iter inner loop.
  type :: bench_case_t
    character(len=128)                     :: name = " "
    procedure(bench_run_iface), pointer, nopass :: run => null()
    integer                                :: case_idx = 0
    integer(int64)                         :: payload_bytes = 0_int64
  end type

  ! Per-process counter so successive `random_bytes` calls within
  ! the same nanosecond still diverge. The bench harness is single-
  ! threaded by design; libitb's worker pool absorbs whatever
  ! parallelism the case body exposes.
  integer(int64), save :: random_counter = 0_int64

contains

  ! ----------------------------------------------------------------
  ! Env-var probes
  ! ----------------------------------------------------------------

  function env_nonce_bits(default_value) result(v)
    integer, intent(in) :: default_value
    integer             :: v
    character(len=64)   :: buf
    integer             :: rc, blen

    call get_environment_variable("ITB_NONCE_BITS", buf, length=blen, status=rc)
    if (rc /= 0 .or. blen == 0) then
      v = default_value
      return
    end if
    select case (trim(buf))
    case ("128"); v = 128
    case ("256"); v = 256
    case ("512"); v = 512
    case default
      write (error_unit, "(A,A,A,I0)") &
        "ITB_NONCE_BITS=", trim(buf), &
        " invalid (expected 128/256/512); using ", default_value
      v = default_value
    end select
  end function

  function env_lock_batch() result(b)
    logical :: b
    character(len=64) :: buf
    integer :: rc, blen

    call get_environment_variable("ITB_LOCKBATCH", buf, length=blen, status=rc)
    if (rc /= 0 .or. blen == 0) then
      b = .false.
      return
    end if
    if (trim(buf) == "0") then
      b = .false.
    else
      b = .true.
    end if
  end function

  function env_lock_seed() result(b)
    logical :: b
    character(len=64) :: buf
    integer :: rc, blen

    call get_environment_variable("ITB_LOCKSEED", buf, length=blen, status=rc)
    if (rc /= 0 .or. blen == 0) then
      b = .false.
      return
    end if
    if (trim(buf) == "0") then
      b = .false.
    else
      b = .true.
    end if
  end function

  ! Returns the optional substring filter as a trimmed Fortran
  ! string. Empty allocatable means "no filter".
  function env_filter() result(s)
    character(:), allocatable :: s
    character(len=256) :: buf
    integer :: rc, blen

    call get_environment_variable("ITB_BENCH_FILTER", buf, length=blen, status=rc)
    if (rc /= 0 .or. blen == 0) then
      s = ""
      return
    end if
    s = trim(buf)
  end function

  function env_min_seconds() result(v)
    real(real64) :: v
    character(len=64) :: buf
    integer :: rc, blen, ios

    call get_environment_variable("ITB_BENCH_MIN_SEC", buf, length=blen, status=rc)
    if (rc /= 0 .or. blen == 0) then
      v = 5.0_real64
      return
    end if
    read (buf, *, iostat=ios) v
    if (ios /= 0 .or. v <= 0.0_real64) then
      write (error_unit, "(A,A,A)") &
        "ITB_BENCH_MIN_SEC=", trim(buf), &
        " invalid (expected positive float); using 5.0"
      v = 5.0_real64
    end if
  end function

  ! ----------------------------------------------------------------
  ! xorshift64* random fill
  ! ----------------------------------------------------------------

  ! Fills `out` with `n` non-deterministic test bytes via a clock-
  ! seeded xorshift64* LCG. Matches the cross-binding bench-fill
  ! algorithm bit-for-bit; the bench harness does not require
  ! cryptographic strength here, only that the payload is non-uniform
  ! and changes between runs so a primitive cannot collapse on a
  ! constant input.
  !
  ! Output kind is `integer(int64)` for portability; callers cast to
  ! `integer(itb_byte_kind)` (an alias for c_int8_t) at the call site
  ! to feed the cipher.
  subroutine random_bytes(out_bytes, n)
    integer(int64), intent(out) :: out_bytes(:)
    integer(int64), intent(in)  :: n
    integer(int64) :: state, v, t0
    integer(int64) :: cr
    integer(int64) :: i, k, take
    integer(int64), parameter :: MULT_HI = int(z"9E3779B97F4A7C15", int64)
    integer(int64), parameter :: ADD_LO  = int(z"BF58476D1CE4E5B9", int64)
    integer(int64), parameter :: XS_MULT = int(z"2545F4914F6CDD1D", int64)
    integer(int64), parameter :: FALLBACK = int(z"DEADBEEFCAFEF00D", int64)

    if (n == 0) return

    random_counter = random_counter + 1_int64

    call system_clock(count=t0, count_rate=cr)

    state = t0 * MULT_HI + random_counter + ADD_LO
    if (state == 0_int64) state = FALLBACK

    i = 1_int64
    do while (i <= n)
      ! xorshift64* -- adequate for non-cryptographic test fill.
      state = ieor(state, ishft(state, -12))
      state = ieor(state, ishft(state,  25))
      state = ieor(state, ishft(state, -27))
      v = state * XS_MULT
      take = min(8_int64, n - i + 1_int64)
      do k = 0_int64, take - 1_int64
        ! Sign-extending shift is fine -- we mask to 8 bits and store
        ! into a 64-bit slot that the caller narrows to int8 anyway.
        out_bytes(i + k) = iand(ishft(v, -8_int64 * k), 255_int64)
      end do
      i = i + take
    end do
  end subroutine

  ! ----------------------------------------------------------------
  ! Substring containment
  ! ----------------------------------------------------------------

  function contains_substr(haystack, needle) result(b)
    character(*), intent(in) :: haystack
    character(*), intent(in) :: needle
    logical                  :: b
    integer :: hlen, nlen, i

    nlen = len(needle)
    if (nlen == 0) then
      b = .true.
      return
    end if
    hlen = len(haystack)
    if (nlen > hlen) then
      b = .false.
      return
    end if
    do i = 1, hlen - nlen + 1
      if (haystack(i:i + nlen - 1) == needle) then
        b = .true.
        return
      end if
    end do
    b = .false.
  end function

  ! ----------------------------------------------------------------
  ! Single-case measurement
  ! ----------------------------------------------------------------

  ! Convergence policy:
  !
  !   1. Warm-up -- one iteration to absorb cache / cold-start
  !      transients before the measured loop.
  !   2. Measurement -- keep doubling the iteration count until the
  !      measured wall-clock duration meets `min_seconds`. Iteration
  !      count is capped at 2^24 so a very fast op cannot escalate
  !      past that ceiling for one batch.
  !   3. Report -- final batch's total ns / iters yields ns/op;
  !      payload_bytes / ns_per_op yields MB/s.
  subroutine measure_case(c, min_seconds)
    type(bench_case_t), intent(in) :: c
    real(real64),       intent(in) :: min_seconds
    integer(int64) :: t0, t1, cr
    integer(int64) :: iters, elapsed_ns, min_ns, max_iters
    real(real64)   :: ns_per_op, mb_per_s
    real(real64)   :: ticks_to_ns

    if (.not. associated(c%run)) then
      write (error_unit, "(A,A)") "measure_case: run pointer null for ", trim(c%name)
      return
    end if

    ! Warm-up.
    call c%run(c%case_idx, 1_int64)

    call system_clock(count_rate=cr)
    if (cr <= 0_int64) then
      write (error_unit, "(A)") "measure_case: system_clock returned non-positive count_rate"
      return
    end if
    ticks_to_ns = 1.0e9_real64 / real(cr, real64)

    min_ns    = int(min_seconds * 1.0e9_real64, int64)
    max_iters = ishft(1_int64, 24)
    iters = 1_int64
    elapsed_ns = 0_int64

    do
      call system_clock(count=t0)
      call c%run(c%case_idx, iters)
      call system_clock(count=t1)
      elapsed_ns = int(real(t1 - t0, real64) * ticks_to_ns, int64)
      if (elapsed_ns >= min_ns) exit
      if (iters >= max_iters) exit
      iters = iters * 2_int64
    end do

    ns_per_op = real(elapsed_ns, real64) / real(iters, real64)
    if (ns_per_op > 0.0_real64) then
      mb_per_s = (real(c%payload_bytes, real64) / (ns_per_op / 1.0e9_real64)) &
                 / real(1024_int64 * 1024_int64, real64)
    else
      mb_per_s = 0.0_real64
    end if

    ! Mirrors `BenchmarkX-N    iters    ns/op    MB/s` Go format,
    ! column-aligned for human reading.
    write (output_unit, "(A,A,I10,A,F14.1,A,A,F9.2,A)") &
        pad_right(trim(c%name), 60), &
        char(9), iters, &
        char(9), ns_per_op, " ns/op", &
        char(9), mb_per_s, " MB/s"
    flush(output_unit)
  end subroutine

  function pad_right(s, width) result(out)
    character(*), intent(in)  :: s
    integer,      intent(in)  :: width
    character(:), allocatable :: out
    if (len(s) >= width) then
      out = s
    else
      out = s // repeat(" ", width - len(s))
    end if
  end function

  ! ----------------------------------------------------------------
  ! Public driver
  ! ----------------------------------------------------------------

  ! Iterates the case array, printing one Go-bench-style line per
  ! case to stdout. Honours ITB_BENCH_FILTER for substring scoping
  ! and ITB_BENCH_MIN_SEC for per-case wall-clock budget.
  subroutine run_all(cases, n_cases)
    type(bench_case_t), intent(in) :: cases(:)
    integer,            intent(in) :: n_cases
    character(:), allocatable :: flt
    real(real64) :: min_seconds
    integer :: i, selected
    integer(int64) :: payload_bytes

    flt = env_filter()
    min_seconds = env_min_seconds()

    selected = 0
    do i = 1, n_cases
      if (len(flt) == 0 .or. contains_substr(trim(cases(i)%name), flt)) then
        selected = selected + 1
      end if
    end do

    if (selected == 0) then
      write (error_unit, "(A,A)") &
        "no bench cases match filter ", &
        trim(merge(flt, "<unset>", len(flt) > 0))
      return
    end if

    payload_bytes = 0_int64
    do i = 1, n_cases
      if (len(flt) == 0 .or. contains_substr(trim(cases(i)%name), flt)) then
        payload_bytes = cases(i)%payload_bytes
        exit
      end if
    end do

    write (output_unit, "(A,I0,A,I0,A,F0.3)") &
        "# benchmarks=", selected, &
        " payload_bytes=", payload_bytes, &
        " min_seconds=", min_seconds
    flush(output_unit)

    do i = 1, n_cases
      if (len(flt) == 0 .or. contains_substr(trim(cases(i)%name), flt)) then
        call measure_case(cases(i), min_seconds)
      end if
    end do
  end subroutine

  ! Measure a single pre-built case at the given min_seconds threshold
  ! and emit one Go-bench-style report line.  Used by the lazy bench
  ! runner in bench_wrapper.f90 — the caller handles filtering and the
  ! header line; this subroutine handles only measurement + output for
  ! one case.
  subroutine measure_one(c, min_seconds)
    type(bench_case_t), intent(in) :: c
    real(real64),       intent(in) :: min_seconds
    call measure_case(c, min_seconds)
  end subroutine

end module bench_common
