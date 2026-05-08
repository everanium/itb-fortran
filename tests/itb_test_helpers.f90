! itb_test_helpers.f90 -- shared assertion vocabulary for the test suite.
!
! Each `tests/test_*.f90` is a standalone program; the helper module
! defines the small set of assertions every test relies on. On any
! assertion failure the helper writes a diagnostic to `error_unit` and
! `error stop`s with code 1, so the standalone program drops into the
! per-test pass/fail accounting in `run_tests.sh` cleanly. On full
! pass, the test program calls `test_pass(name)` exactly once at the
! end and exits with status 0.
!
! Tests do not print intermediate progress beyond the single PASS or
! FAIL line; the runner captures stdout / exit code.

module itb_test_helpers
  use, intrinsic :: iso_fortran_env, only: error_unit, output_unit
  use itb_kinds
  use itb_errors, only: STATUS_OK, itb_status_to_string
  implicit none
  private

  public :: assert_status_ok
  public :: assert_status_eq
  public :: assert_true
  public :: assert_false
  public :: assert_int_eq
  public :: assert_size_eq
  public :: assert_string_eq
  public :: assert_bytes_eq
  public :: assert_u64_array_eq
  public :: test_pass
  public :: test_fail

contains

  subroutine test_fail(test_name, message)
    character(*), intent(in) :: test_name, message
    write (error_unit, "(A,A,A,A)") "FAIL: ", trim(test_name), ": ", trim(message)
    error stop 1
  end subroutine

  subroutine test_pass(test_name)
    character(*), intent(in) :: test_name
    write (output_unit, "(A,A)") "PASS: ", trim(test_name)
    flush (output_unit)
  end subroutine

  subroutine assert_status_ok(test_name, label, status)
    character(*),             intent(in) :: test_name, label
    integer(itb_status_kind), intent(in) :: status
    character(:), allocatable :: name, msg
    if (status == STATUS_OK) return
    name = itb_status_to_string(status)
    allocate (character(256) :: msg)
    write (msg, "(A,A,I0,A,A,A)") trim(label), " -- expected STATUS_OK, got ", &
                                    status, " (", trim(name), ")"
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_status_eq(test_name, label, status, expected)
    character(*),             intent(in) :: test_name, label
    integer(itb_status_kind), intent(in) :: status, expected
    character(:), allocatable :: got_name, exp_name, msg
    if (status == expected) return
    got_name = itb_status_to_string(status)
    exp_name = itb_status_to_string(expected)
    allocate (character(384) :: msg)
    write (msg, "(A,A,I0,A,A,A,I0,A,A,A)") trim(label), &
        " -- expected ", expected, " (", trim(exp_name), &
        "), got ", status, " (", trim(got_name), ")"
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_true(test_name, label, condition)
    character(*), intent(in) :: test_name, label
    logical,      intent(in) :: condition
    character(:), allocatable :: msg
    if (condition) return
    msg = trim(label) // " -- expected .true., got .false."
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_false(test_name, label, condition)
    character(*), intent(in) :: test_name, label
    logical,      intent(in) :: condition
    character(:), allocatable :: msg
    if (.not. condition) return
    msg = trim(label) // " -- expected .false., got .true."
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_int_eq(test_name, label, got, expected)
    character(*), intent(in) :: test_name, label
    integer,      intent(in) :: got, expected
    character(:), allocatable :: msg
    if (got == expected) return
    allocate (character(256) :: msg)
    write (msg, "(A,A,I0,A,I0)") trim(label), " -- expected ", expected, ", got ", got
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_size_eq(test_name, label, got, expected)
    character(*),                intent(in) :: test_name, label
    integer(itb_size_kind),      intent(in) :: got, expected
    character(:), allocatable :: msg
    if (got == expected) return
    allocate (character(256) :: msg)
    write (msg, "(A,A,I0,A,I0)") trim(label), " -- expected ", expected, ", got ", got
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_string_eq(test_name, label, got, expected)
    character(*), intent(in) :: test_name, label, got, expected
    character(:), allocatable :: msg
    if (trim(got) == trim(expected)) return
    msg = trim(label) // " -- expected '" // trim(expected) // "', got '" // trim(got) // "'"
    call test_fail(test_name, msg)
  end subroutine

  subroutine assert_bytes_eq(test_name, label, got, expected)
    character(*),           intent(in) :: test_name, label
    integer(itb_byte_kind), intent(in) :: got(:), expected(:)
    character(:), allocatable :: msg
    integer :: i, ng, ne
    ng = size(got); ne = size(expected)
    if (ng /= ne) then
      allocate (character(256) :: msg)
      write (msg, "(A,A,I0,A,I0)") trim(label), &
          " -- length mismatch: expected ", ne, ", got ", ng
      call test_fail(test_name, msg)
    end if
    do i = 1, ng
      if (got(i) /= expected(i)) then
        allocate (character(256) :: msg)
        write (msg, "(A,A,I0,A,I0,A,I0)") trim(label), &
            " -- byte mismatch at index ", i, &
            ": expected ", iand(int(expected(i)), 255), &
            ", got ", iand(int(got(i)), 255)
        call test_fail(test_name, msg)
      end if
    end do
  end subroutine

  subroutine assert_u64_array_eq(test_name, label, got, expected)
    character(*),          intent(in) :: test_name, label
    integer(itb_u64_kind), intent(in) :: got(:), expected(:)
    character(:), allocatable :: msg
    integer :: i, ng, ne
    ng = size(got); ne = size(expected)
    if (ng /= ne) then
      allocate (character(256) :: msg)
      write (msg, "(A,A,I0,A,I0)") trim(label), &
          " -- length mismatch: expected ", ne, ", got ", ng
      call test_fail(test_name, msg)
    end if
    do i = 1, ng
      if (got(i) /= expected(i)) then
        allocate (character(256) :: msg)
        write (msg, "(A,A,I0)") trim(label), " -- u64 element mismatch at index ", i
        call test_fail(test_name, msg)
      end if
    end do
  end subroutine

end module itb_test_helpers
