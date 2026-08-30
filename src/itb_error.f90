! itb_error.f90 -- error record carried by every fallible binding call.
!
! Each public subroutine takes a trailing `type(itb_error_t),
! intent(out) :: err` argument. On success `err%status` is
! ITB_STATUS_OK and `err%message` is empty; on failure `err%status`
! carries the libitb status code and `err%message` the ITB_LastError
! diagnostic captured immediately after the failing call.
!
! ITB_LastError is process-global last-write-wins: under concurrent
! FFI use the textual diagnostic may belong to a different call. The
! status code is always attributable.

module itb_error
  use, intrinsic :: iso_c_binding, only: c_int, c_size_t, c_char, &
      c_ptr, c_loc
  use itb_status
  use itb_ffi, only: c_itb_last_error, itb_from_cstr
  implicit none
  private

  public :: itb_error_t, itb_ok, itb_error_clear, itb_error_set, &
            itb_error_text

  type :: itb_error_t
    integer(c_int)            :: status = ITB_STATUS_OK
    character(:), allocatable :: message
  end type

contains

  ! .true. when the record carries no error.
  pure function itb_ok(err) result(ok)
    type(itb_error_t), intent(in) :: err
    logical :: ok
    ok = (err%status == ITB_STATUS_OK)
  end function

  ! Reset the record to the OK state.
  subroutine itb_error_clear(err)
    type(itb_error_t), intent(out) :: err
    err%status = ITB_STATUS_OK
    err%message = ""
  end subroutine

  ! Populate the record from a libitb return code. Non-OK codes pull
  ! the ITB_LastError diagnostic; OK clears the record.
  subroutine itb_error_set(err, rc)
    type(itb_error_t), intent(out) :: err
    integer(c_int), intent(in)     :: rc

    err%status = rc
    if (rc == ITB_STATUS_OK) then
      err%message = ""
    else
      call fetch_last_error(err%message)
    end if
  end subroutine

  ! "status <n> (<label>): <diagnostic>" -- one-line rendering for
  ! logs and test failure messages.
  function itb_error_text(err) result(txt)
    type(itb_error_t), intent(in) :: err
    character(:), allocatable     :: txt
    character(len=12) :: code

    write (code, '(i0)') err%status
    txt = "status "//trim(code)//" ("//itb_status_label(err%status)//")"
    if (allocated(err%message)) then
      if (len(err%message) > 0) txt = txt//": "//err%message
    end if
  end function

  subroutine fetch_last_error(msg)
    character(:), allocatable, intent(out) :: msg
    character(kind=c_char), target :: buf(1024)
    integer(c_size_t) :: n
    integer(c_int)    :: rc

    n = 0_c_size_t
    rc = c_itb_last_error(c_loc(buf(1)), int(size(buf), c_size_t), n)
    if (rc /= ITB_STATUS_OK) then
      ! Diagnostic longer than the local buffer (or unreadable) --
      ! keep the status code, drop the text.
      msg = ""
      return
    end if
    call itb_from_cstr(buf, n, msg)
  end subroutine

end module itb_error
