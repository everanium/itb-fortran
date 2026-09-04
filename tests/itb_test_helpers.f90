! itb_test_helpers.f90 -- shared assertion module for the test
! programs. Each tests/test_*.f90 is a standalone program; on any
! failed assertion the process prints a diagnostic and exits with a
! non-zero status (run_tests.sh counts per-binary pass / fail).

module itb_test_helpers
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t
  use, intrinsic :: iso_fortran_env, only: error_unit, int64
  use itb
  implicit none
  private

  public :: check, expect_ok, expect_status, check_bytes_equal, &
            test_done, byte_of, fill_mod, fill_xorshift, load_from

contains

  ! Hard assertion: prints the label and aborts on a false condition.
  subroutine check(cond, label)
    logical, intent(in)      :: cond
    character(*), intent(in) :: label

    if (.not. cond) then
      write (error_unit, '(a)') "FAIL: "//label
      error stop 1
    end if
  end subroutine

  ! Asserts the error record carries no error.
  subroutine expect_ok(err, label)
    type(itb_error_t), intent(in) :: err
    character(*), intent(in)      :: label

    if (.not. itb_ok(err)) then
      write (error_unit, '(a)') "FAIL: "//label//": "//itb_error_text(err)
      error stop 1
    end if
  end subroutine

  ! Asserts the error record carries exactly the expected status.
  subroutine expect_status(err, expected, label)
    type(itb_error_t), intent(in) :: err
    integer(c_int), intent(in)    :: expected
    character(*), intent(in)      :: label

    if (err%status /= expected) then
      write (error_unit, '(a,i0,a)') "FAIL: "//label// &
          ": expected status ", expected, ", got "//itb_error_text(err)
      error stop 1
    end if
  end subroutine

  ! Asserts two byte arrays are identical (length + content).
  subroutine check_bytes_equal(a, b, label)
    integer(c_int8_t), intent(in) :: a(:), b(:)
    character(*), intent(in)      :: label

    if (size(a) /= size(b)) then
      write (error_unit, '(a,i0,a,i0)') "FAIL: "//label// &
          ": length mismatch ", size(a), " vs ", size(b)
      error stop 1
    end if
    if (size(a) > 0) then
      if (.not. all(a == b)) then
        write (error_unit, '(a)') "FAIL: "//label//": content mismatch"
        error stop 1
      end if
    end if
  end subroutine

  ! Prints the per-binary pass line (reaching here means every
  ! assertion held).
  subroutine test_done(name)
    character(*), intent(in) :: name
    print '(a)', "PASS "//name
  end subroutine

  ! Maps 0..255 (any integer, taken modulo 256) onto the signed
  ! int8 byte carrying the same bit pattern.
  pure function byte_of(v) result(b)
    integer, intent(in) :: v
    integer(c_int8_t)   :: b
    integer :: m

    m = modulo(v, 256)
    if (m > 127) m = m - 256
    b = int(m, c_int8_t)
  end function

  ! Deterministic fill: buf(i) = (i-1) mod m.
  subroutine fill_mod(buf, m)
    integer(c_int8_t), intent(out) :: buf(:)
    integer, intent(in)            :: m
    integer :: i

    do i = 1, size(buf)
      buf(i) = byte_of(modulo(i - 1, m))
    end do
  end subroutine

  ! Save -> Load handshake: a receiver reconstructed from the
  ! sender's current blob.
  subroutine load_from(sender, receiver, err)
    type(itb_pipeline_t), intent(in)  :: sender
    type(itb_pipeline_t), intent(out) :: receiver
    type(itb_error_t), intent(out)    :: err
    integer(c_int8_t), allocatable :: blob(:)

    call itb_pipeline_save(sender, blob, err)
    if (.not. itb_ok(err)) return
    call itb_pipeline_load(receiver, blob, err)
  end subroutine

  ! Deterministic non-trivial payload (xorshift64 fill).
  subroutine fill_xorshift(buf, seed)
    integer(c_int8_t), intent(out) :: buf(:)
    integer(int64), intent(in)     :: seed
    integer(int64) :: x
    integer :: i

    x = ior(seed, 1_int64)
    do i = 1, size(buf)
      x = ieor(x, ishft(x, 13))
      x = ieor(x, ishft(x, -7))
      x = ieor(x, ishft(x, 17))
      buf(i) = int(ibits(x, 0, 8) - merge(256_int64, 0_int64, ibits(x, 0, 8) > 127), c_int8_t)
    end do
  end subroutine

end module itb_test_helpers
