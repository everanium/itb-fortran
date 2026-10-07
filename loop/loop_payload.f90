! Plaintext content: the payload modes, the seeded per-worker
! generator, and the buffer fill from the operating-system CSPRNG.

module loop_payload
  use, intrinsic :: iso_c_binding
  use loop_state
  implicit none
  private

  public :: payload_mode_name, parse_payload_mode, seed_worker
  public :: fill_payload, fill_random

  ! Payload mode selector values for the --payload-mode flag.
  !
  !   - fixed: one CSPRNG-generated buffer per worker, held unchanged
  !     for the whole run (the default).
  !   - rotating: the buffer is regenerated before every iteration,
  !     so no two encrypt calls see the same plaintext.
  !   - pattern-zero / pattern-ff: degenerate constant fills (all
  !     0x00 / all 0xFF) probing minimum-entropy plaintext handling.
  !   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
  !     structured text.
  character(len=13), parameter :: PAYLOAD_NAMES(0:4) = [ &
      "fixed        ", "rotating     ", "pattern-zero ", &
      "pattern-ff   ", "pattern-ascii"]

  ! splitmix64 constants as signed decimals: the BOZ literal forms
  ! are out of range for a signed 64-bit integer, which a strict
  ! Fortran 2008 compile rejects.
  integer(c_int64_t), parameter :: GAMMA = -7046029254386353131_c_int64_t
  integer(c_int64_t), parameter :: MIX1 = -4658895280553007687_c_int64_t
  integer(c_int64_t), parameter :: MIX2 = -7723592293110705685_c_int64_t

contains

  ! Low byte of a 64-bit value as a signed 8-bit integer: the Fortran
  ! integer kinds are all signed, so 0x80..0xFF cross as negatives.
  pure function to_i8(x) result(b)
    integer(c_int64_t), intent(in) :: x
    integer(c_int8_t)              :: b
    integer(c_int64_t) :: m

    m = iand(x, 255_c_int64_t)
    if (m >= 128_c_int64_t) m = m - 256_c_int64_t
    b = int(m, c_int8_t)
  end function

  function payload_mode_name(mode) result(s)
    integer, intent(in)       :: mode
    character(:), allocatable :: s
    s = trim(PAYLOAD_NAMES(mode))
  end function

  function parse_payload_mode(text, mode) result(ok)
    character(*), intent(in) :: text
    integer, intent(out)     :: mode
    logical                  :: ok
    integer :: i

    mode = PAYLOAD_FIXED
    ok = .false.
    do i = 0, 4
      if (text == trim(PAYLOAD_NAMES(i))) then
        mode = i
        ok = .true.
        return
      end if
    end do
  end function

  ! Seeded plaintext. The seed makes plaintext content reproducible
  ! so a failing iteration can be replayed with the same bytes; it
  ! governs nothing else -- pipeline keys, nonces and masters stay
  ! CSPRNG-drawn, so a seeded run is a reproduction aid and never a
  ! security test. Each worker's stream is domain-separated by its id
  ! so seeded workers still hold pairwise-distinct buffers under the
  ! fixed and rotating modes. The generator is splitmix64: a few
  ! lines in any language, which is why it is the one every binding
  ! uses.
  function seed_worker(seed, worker_id) result(state)
    integer(c_int64_t), intent(in) :: seed
    integer, intent(in)            :: worker_id
    integer(c_int64_t)             :: state
    state = seed + int(worker_id, c_int64_t) + 1_c_int64_t
  end function

  function splitmix64(state) result(v)
    integer(c_int64_t), intent(inout) :: state
    integer(c_int64_t)                :: v, z

    state = state + GAMMA
    z = state
    z = ieor(z, ishft(z, -30)) * MIX1
    z = ieor(z, ishft(z, -27)) * MIX2
    v = ieor(z, ishft(z, -31))
  end function

  ! Fills buf from the operating-system CSPRNG. Fortran-specific:
  ! getrandom returns at most ~33 MiB per call and may return short
  ! on a signal, so the fill loops until every byte is in place.
  function fill_random(buf) result(ok)
    integer(c_int8_t), intent(out), target, contiguous :: buf(:)
    logical                                           :: ok
    integer(c_intptr_t) :: off, got
    integer(c_int64_t)  :: total

    ok = .true.
    total = int(size(buf, kind=c_int64_t), c_int64_t)
    if (total <= 0_c_int64_t) return
    off = 0_c_intptr_t
    do while (off < int(total, c_intptr_t))
      got = c_getrandom(c_loc(buf(int(off) + 1)), &
                        int(total - int(off, c_int64_t), c_size_t), 0_c_int)
      if (got <= 0_c_intptr_t) then
        ok = .false.
        return
      end if
      off = off + got
    end do
  end function

  ! Writes one plaintext buffer according to the payload mode. The
  ! fixed and rotating modes draw from the seeded generator when the
  ! run is seeded and from the OS CSPRNG otherwise; the pattern modes
  ! are deterministic regardless of the seed.
  function fill_payload(mode, seeded, rng, buf) result(ok)
    integer, intent(in)                               :: mode
    logical, intent(in)                               :: seeded
    integer(c_int64_t), intent(inout)                 :: rng
    integer(c_int8_t), intent(out), target, contiguous :: buf(:)
    logical                                           :: ok
    integer(c_int64_t) :: i, n, v
    integer            :: k, take

    ok = .true.
    n = int(size(buf, kind=c_int64_t), c_int64_t)
    select case (mode)
    case (PAYLOAD_FIXED, PAYLOAD_ROTATING)
      if (.not. seeded) then
        ok = fill_random(buf)
        return
      end if
      i = 1_c_int64_t
      do while (i <= n)
        v = splitmix64(rng)
        take = int(min(8_c_int64_t, n - i + 1_c_int64_t))
        do k = 0, take - 1
          buf(i + int(k, c_int64_t)) = to_i8(ishft(v, -8 * k))
        end do
        i = i + 8_c_int64_t
      end do
    case (PAYLOAD_PATTERN_ZERO)
      buf = 0_c_int8_t
    case (PAYLOAD_PATTERN_FF)
      buf = -1_c_int8_t
    case (PAYLOAD_PATTERN_ASCII)
      do i = 1_c_int64_t, n
        buf(i) = to_i8(int(iachar('A'), c_int64_t) &
                       + mod(i - 1_c_int64_t, 26_c_int64_t))
      end do
    case default
      ok = .false.
    end select
  end function

end module loop_payload
