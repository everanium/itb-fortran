! common.f90 -- shared timing + reporting helpers for the Fortran
! binding micro-benchmarks. Wall-clock via system_clock (monotonic);
! output is a fixed-width table:
!
!   bench             size     mb_per_sec
!   message           1 MiB    <n>
!   ...
!
! Bench configuration is driven by environment variables so a
! side-by-side comparison with the root Go bench harness is
! straightforward:
!
!   ITB_NONCE_BITS     (default 512)
!   ITB_KEY_BITS       (default 1024)
!   ITB_WITH_PARALLAX  (default false)
!   ITB_WITH_WRAPPER   (default false)
!   ITB_INNER_HASH     (default: profile-defined)
!   ITB_PROFILE        (default: per-binary fallback)
!   ITB_BENCH_MIN_SEC  (default 5)

module bench_common
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t, c_size_t, &
      c_intptr_t, c_ptr, c_loc
  use, intrinsic :: iso_fortran_env, only: error_unit, int64, real64
  use itb
  implicit none
  private

  public :: bench_min_seconds, bench_build_opts, bench_profile_name, &
            bench_now, bench_header, bench_report, csprng_fill

  ! Iteration floor regardless of the wall-clock budget. The timing
  ! loop lives in each bench program (an internal-procedure callback
  ! would force a gcc trampoline and an executable stack); the shape
  ! is: one untimed warm-up, then iterate until
  ! `elapsed >= bench_min_seconds() .and. iters >= BENCH_MIN_ITERS`,
  ! then one bench_report call.
  integer, parameter, public :: BENCH_MIN_ITERS = 3

  interface
    ! ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
    function c_getrandom(buf, buflen, flags) &
        bind(C, name="getrandom") result(n)
      import :: c_ptr, c_size_t, c_int, c_intptr_t
      type(c_ptr), value       :: buf
      integer(c_size_t), value :: buflen
      integer(c_int), value    :: flags
      integer(c_intptr_t)      :: n
    end function
  end interface

contains

  ! Environment variable value, or the default when unset / empty.
  function env_or(name, default) result(v)
    character(*), intent(in)  :: name
    character(*), intent(in)  :: default
    character(:), allocatable :: v
    character(len=256) :: raw
    integer :: l, stat

    call get_environment_variable(name, value=raw, length=l, status=stat)
    if (stat /= 0 .or. l <= 0) then
      v = default
    else
      v = trim(raw)
    end if
  end function

  ! Per-case wall-clock budget in seconds (env: ITB_BENCH_MIN_SEC).
  function bench_min_seconds() result(sec)
    real(real64) :: sec
    character(:), allocatable :: raw
    integer :: stat

    raw = env_or("ITB_BENCH_MIN_SEC", "5")
    read (raw, *, iostat=stat) sec
    if (stat /= 0 .or. sec <= 0.0_real64) sec = 5.0_real64
  end function

  ! Reads the bench-shape env vars into an opts builder. Defaults
  ! match the root Go BENCH3.md pin so numbers are directly
  ! comparable.
  subroutine bench_build_opts(opts)
    type(itb_opts_t), intent(out) :: opts
    character(:), allocatable :: v

    call itb_opts_set(opts, "nonceBits", env_or("ITB_NONCE_BITS", "512"))
    call itb_opts_set(opts, "keyBits", env_or("ITB_KEY_BITS", "1024"))
    v = env_or("ITB_WITH_PARALLAX", "false")
    call itb_opts_set(opts, "withParallax", &
        trim(merge("true ", "false", v == "true" .or. v == "1")))
    v = env_or("ITB_WITH_WRAPPER", "false")
    call itb_opts_set(opts, "withWrapper", &
        trim(merge("true ", "false", v == "true" .or. v == "1")))
    v = env_or("ITB_INNER_HASH", "")
    if (len(v) > 0) call itb_opts_set(opts, "innerHash", v)
    v = env_or("ITB_MAC_NAME", "")
    if (len(v) > 0) call itb_opts_set(opts, "macName", v)
  end subroutine

  ! ITB_PROFILE env override, or the per-binary fallback.
  function bench_profile_name(fallback) result(name)
    character(*), intent(in)  :: fallback
    character(:), allocatable :: name
    name = env_or("ITB_PROFILE", fallback)
  end function

  ! Monotonic wall-clock seconds.
  function bench_now() result(sec)
    real(real64) :: sec
    integer(int64) :: count, rate

    call system_clock(count, rate)
    sec = real(count, real64) / real(rate, real64)
  end function

  subroutine bench_header()
    character(len=17) :: c1
    character(len=8)  :: c2

    c1 = "bench"
    c2 = "size"
    print '(a,1x,a,1x,a)', c1, c2, "mb_per_sec"
  end subroutine

  ! Prints one table row from an accumulated (iters, elapsed) pair.
  subroutine bench_report(name, size_bytes, iters, elapsed)
    character(*), intent(in)   :: name
    integer, intent(in)        :: size_bytes
    integer(int64), intent(in) :: iters
    real(real64), intent(in)   :: elapsed
    real(real64) :: mb

    mb = real(size_bytes, real64) * real(iters, real64) &
         / (1024.0_real64 * 1024.0_real64)
    call print_row(name, size_label(size_bytes), mb / elapsed)
  end subroutine

  subroutine print_row(name, label, rate)
    character(*), intent(in) :: name
    character(*), intent(in) :: label
    real(real64), intent(in) :: rate
    character(len=17) :: c1
    character(len=8)  :: c2

    c1 = name
    c2 = label
    print '(a,1x,a,1x,f0.1)', c1, c2, rate
  end subroutine

  function size_label(size_bytes) result(label)
    integer, intent(in) :: size_bytes
    character(len=8)    :: label

    if (size_bytes >= 2**20) then
      write (label, '(i0,a)') size_bytes / 2**20, " MiB"
    else
      write (label, '(i0,a)') size_bytes / 2**10, " KiB"
    end if
  end function

  ! CSPRNG-fill so plaintext content matches the root Go bench
  ! (crypto/rand). getrandom returns at most ~33 MiB per call on
  ! Linux, so loop until the whole buffer is filled. Not for use
  ! inside timing loops.
  subroutine csprng_fill(buf)
    integer(c_int8_t), intent(inout), target, contiguous :: buf(:)
    integer :: off
    integer(c_intptr_t) :: got

    off = 0
    do while (off < size(buf))
      got = c_getrandom(c_loc(buf(off + 1)), &
          int(size(buf) - off, c_size_t), 0_c_int)
      if (got <= 0) then
        write (error_unit, '(a)') "csprng_fill: getrandom failed"
        error stop 1
      end if
      off = off + int(got)
    end do
  end subroutine

end module bench_common
