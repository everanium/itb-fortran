! test_config.f90 -- process-global configuration round-trip tests.
!
! libitb exposes five process-wide atomics through the
! itb_set_*  / itb_get_* surface: bit_soup, lock_soup, max_workers,
! nonce_bits, barrier_fill. Each test snapshots the prior value, drives
! it through the valid range, asserts the getter mirrors the setter,
! and restores the snapshot before returning. Per-binary process
! isolation gives this test program its own libitb global state, so
! the snapshot-and-restore discipline is internal hygiene rather than
! cross-test protection.
!
! Validation rejection paths. nonce_bits accepts {128, 256, 512} and
! rejects every other value as STATUS_BAD_INPUT. barrier_fill accepts
! powers of two in {1, 2, 4, 8, 16, 32} and rejects everything else
! the same way. The setter raises via raise_itb_error on an invalid
! value, so observing the rejection without terminating the test
! requires going through the low-level itb_set_*_c FFI directly.

program test_config
  use itb_kinds
  use itb_library
  use itb_errors
  use itb_sys, only: itb_set_nonce_bits_c, itb_set_barrier_fill_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_config"

  call test_bit_soup_roundtrip()
  call test_lock_soup_roundtrip()
  call test_max_workers_roundtrip()
  call test_nonce_bits_validation()
  call test_barrier_fill_validation()

  call test_pass(TEST_NAME)

contains

  subroutine test_bit_soup_roundtrip()
    integer(itb_int32_kind) :: orig
    orig = itb_get_bit_soup()
    call itb_set_bit_soup(1)
    call assert_int_eq(TEST_NAME, "bit_soup set to 1", int(itb_get_bit_soup()), 1)
    call itb_set_bit_soup(0)
    call assert_int_eq(TEST_NAME, "bit_soup set to 0", int(itb_get_bit_soup()), 0)
    call itb_set_bit_soup(int(orig))
  end subroutine

  subroutine test_lock_soup_roundtrip()
    integer(itb_int32_kind) :: orig
    orig = itb_get_lock_soup()
    call itb_set_lock_soup(1)
    call assert_int_eq(TEST_NAME, "lock_soup set to 1", int(itb_get_lock_soup()), 1)
    call itb_set_lock_soup(int(orig))
  end subroutine

  subroutine test_max_workers_roundtrip()
    integer(itb_int32_kind) :: orig
    orig = itb_get_max_workers()
    call itb_set_max_workers(4)
    call assert_int_eq(TEST_NAME, "max_workers set to 4", int(itb_get_max_workers()), 4)
    call itb_set_max_workers(int(orig))
  end subroutine

  subroutine test_nonce_bits_validation()
    integer, parameter :: VALID(3) = [128, 256, 512]
    integer, parameter :: BAD(4)   = [0, 1, 192, 1024]
    integer(itb_int32_kind)  :: orig
    integer(itb_status_kind) :: rc
    integer :: i

    orig = itb_get_nonce_bits()
    do i = 1, size(VALID)
      call itb_set_nonce_bits(VALID(i))
      call assert_int_eq(TEST_NAME, "nonce_bits accepts valid", &
                          int(itb_get_nonce_bits()), VALID(i))
    end do
    do i = 1, size(BAD)
      rc = itb_set_nonce_bits_c(int(BAD(i), c_int))
      call assert_status_eq(TEST_NAME, "nonce_bits rejects invalid", &
                             rc, STATUS_BAD_INPUT)
    end do
    call itb_set_nonce_bits(int(orig))
  end subroutine

  subroutine test_barrier_fill_validation()
    integer, parameter :: VALID(6) = [1, 2, 4, 8, 16, 32]
    integer, parameter :: BAD(5)   = [0, 3, 5, 7, 64]
    integer(itb_int32_kind)  :: orig
    integer(itb_status_kind) :: rc
    integer :: i

    orig = itb_get_barrier_fill()
    do i = 1, size(VALID)
      call itb_set_barrier_fill(VALID(i))
      call assert_int_eq(TEST_NAME, "barrier_fill accepts valid", &
                          int(itb_get_barrier_fill()), VALID(i))
    end do
    do i = 1, size(BAD)
      rc = itb_set_barrier_fill_c(int(BAD(i), c_int))
      call assert_status_eq(TEST_NAME, "barrier_fill rejects invalid", &
                             rc, STATUS_BAD_INPUT)
    end do
    call itb_set_barrier_fill(int(orig))
  end subroutine

end program test_config
