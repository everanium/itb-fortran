! itb_errors.f90 -- libitb status constants + the canonical
! `raise_itb_error` helper.
!
! libitb returns `int` status codes from every FFI entry point. The
! binding's wrapper layer uniformly converts every non-OK status into
! a call to `raise_itb_error`, which prints a diagnostic on
! `error_unit` and halts the program via `error stop 1` (Fortran
! 2018). The only exception is the free-function stream subroutines,
! which accept an `intent(out) :: status :: integer(itb_status_kind)`
! argument and let the caller branch on the raw status code instead
! of halting.
!
! Status code numbering is the canonical libitb enum: stable across
! releases, identical across every binding. The Go-side source of
! truth lives at `cmd/cshared/internal/capi/errors.go`; this module
! mirrors it byte-for-byte.

module itb_errors
  use itb_kinds
  use itb_strings, only: c_buffer_to_fortran_string
  use itb_sys,     only: itb_last_error_c
  implicit none
  private

  public :: raise_itb_error
  public :: itb_status_to_string
  public :: itb_last_error_message

  ! Canonical status codes. Numbers are load-bearing and must stay in
  ! lock-step with libitb. The 0..10 block covers the low-level
  ! Encrypt / Decrypt path; 11..18 covers the Easy Mode Encryptor
  ! surface; 19..22 covers the native Blob persistence; 99 is the
  ! catch-all internal sentinel.
  integer(itb_status_kind), parameter, public :: STATUS_OK                          = 0
  integer(itb_status_kind), parameter, public :: STATUS_BAD_HASH                    = 1
  integer(itb_status_kind), parameter, public :: STATUS_BAD_KEY_BITS                = 2
  integer(itb_status_kind), parameter, public :: STATUS_BAD_HANDLE                  = 3
  integer(itb_status_kind), parameter, public :: STATUS_BAD_INPUT                   = 4
  integer(itb_status_kind), parameter, public :: STATUS_BUFFER_TOO_SMALL            = 5
  integer(itb_status_kind), parameter, public :: STATUS_ENCRYPT_FAILED              = 6
  integer(itb_status_kind), parameter, public :: STATUS_DECRYPT_FAILED              = 7
  integer(itb_status_kind), parameter, public :: STATUS_SEED_WIDTH_MIX              = 8
  integer(itb_status_kind), parameter, public :: STATUS_BAD_MAC                     = 9
  integer(itb_status_kind), parameter, public :: STATUS_MAC_FAILURE                 = 10

  integer(itb_status_kind), parameter, public :: STATUS_EASY_CLOSED                 = 11
  integer(itb_status_kind), parameter, public :: STATUS_EASY_MALFORMED              = 12
  integer(itb_status_kind), parameter, public :: STATUS_EASY_VERSION_TOO_NEW        = 13
  integer(itb_status_kind), parameter, public :: STATUS_EASY_UNKNOWN_PRIMITIVE      = 14
  integer(itb_status_kind), parameter, public :: STATUS_EASY_UNKNOWN_MAC            = 15
  integer(itb_status_kind), parameter, public :: STATUS_EASY_BAD_KEY_BITS           = 16
  integer(itb_status_kind), parameter, public :: STATUS_EASY_MISMATCH               = 17
  integer(itb_status_kind), parameter, public :: STATUS_EASY_LOCKSEED_AFTER_ENCRYPT = 18

  integer(itb_status_kind), parameter, public :: STATUS_BLOB_MODE_MISMATCH          = 19
  integer(itb_status_kind), parameter, public :: STATUS_BLOB_MALFORMED              = 20
  integer(itb_status_kind), parameter, public :: STATUS_BLOB_VERSION_TOO_NEW        = 21
  integer(itb_status_kind), parameter, public :: STATUS_BLOB_TOO_MANY_OPTS          = 22

  integer(itb_status_kind), parameter, public :: STATUS_STREAM_TRUNCATED            = 23
  integer(itb_status_kind), parameter, public :: STATUS_STREAM_AFTER_FINAL          = 24

  integer(itb_status_kind), parameter, public :: STATUS_INTERNAL                    = 99

contains

  ! Map a status code to its constant name. Used by `raise_itb_error`
  ! to assemble a diagnostic before `error stop`.
  pure function itb_status_to_string(status) result(name)
    integer(itb_status_kind), intent(in) :: status
    character(:), allocatable            :: name

    select case (status)
    case (STATUS_OK);                          name = "STATUS_OK"
    case (STATUS_BAD_HASH);                    name = "STATUS_BAD_HASH"
    case (STATUS_BAD_KEY_BITS);                name = "STATUS_BAD_KEY_BITS"
    case (STATUS_BAD_HANDLE);                  name = "STATUS_BAD_HANDLE"
    case (STATUS_BAD_INPUT);                   name = "STATUS_BAD_INPUT"
    case (STATUS_BUFFER_TOO_SMALL);            name = "STATUS_BUFFER_TOO_SMALL"
    case (STATUS_ENCRYPT_FAILED);              name = "STATUS_ENCRYPT_FAILED"
    case (STATUS_DECRYPT_FAILED);              name = "STATUS_DECRYPT_FAILED"
    case (STATUS_SEED_WIDTH_MIX);              name = "STATUS_SEED_WIDTH_MIX"
    case (STATUS_BAD_MAC);                     name = "STATUS_BAD_MAC"
    case (STATUS_MAC_FAILURE);                 name = "STATUS_MAC_FAILURE"
    case (STATUS_EASY_CLOSED);                 name = "STATUS_EASY_CLOSED"
    case (STATUS_EASY_MALFORMED);              name = "STATUS_EASY_MALFORMED"
    case (STATUS_EASY_VERSION_TOO_NEW);        name = "STATUS_EASY_VERSION_TOO_NEW"
    case (STATUS_EASY_UNKNOWN_PRIMITIVE);      name = "STATUS_EASY_UNKNOWN_PRIMITIVE"
    case (STATUS_EASY_UNKNOWN_MAC);            name = "STATUS_EASY_UNKNOWN_MAC"
    case (STATUS_EASY_BAD_KEY_BITS);           name = "STATUS_EASY_BAD_KEY_BITS"
    case (STATUS_EASY_MISMATCH);               name = "STATUS_EASY_MISMATCH"
    case (STATUS_EASY_LOCKSEED_AFTER_ENCRYPT); name = "STATUS_EASY_LOCKSEED_AFTER_ENCRYPT"
    case (STATUS_BLOB_MODE_MISMATCH);          name = "STATUS_BLOB_MODE_MISMATCH"
    case (STATUS_BLOB_MALFORMED);              name = "STATUS_BLOB_MALFORMED"
    case (STATUS_BLOB_VERSION_TOO_NEW);        name = "STATUS_BLOB_VERSION_TOO_NEW"
    case (STATUS_BLOB_TOO_MANY_OPTS);          name = "STATUS_BLOB_TOO_MANY_OPTS"
    case (STATUS_STREAM_TRUNCATED);            name = "STATUS_STREAM_TRUNCATED"
    case (STATUS_STREAM_AFTER_FINAL);          name = "STATUS_STREAM_AFTER_FINAL"
    case (STATUS_INTERNAL);                    name = "STATUS_INTERNAL"
    case default;                              name = "STATUS_UNKNOWN"
    end select
  end function

  ! Read the most recent libitb diagnostic via two-call probe of
  ! `ITB_LastError`. Returns an empty string if no error is recorded
  ! or the probe itself fails. Process-wide TLS: the message reflects
  ! the calling thread's most recent libitb error.
  function itb_last_error_message() result(msg)
    character(:), allocatable :: msg
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    msg = ""

    ! Probe with cap=0 to discover the visible length.
    out_len = 0_itb_size_kind
    rc = itb_last_error_c(c_null_ptr, 0_itb_size_kind, out_len)

    ! libitb returns BUFFER_TOO_SMALL on the probe (or OK with
    ! out_len=0 if no error is recorded). Anything else means the
    ! diagnostic itself is unreadable -- return empty.
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) return
    if (out_len == 0) return

    cap = out_len + 1_itb_size_kind
    allocate (buf(cap))
    rc = itb_last_error_c(c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) return

    call c_buffer_to_fortran_string(buf, out_len, msg)
  end function

  ! Halt the program with a diagnostic for any non-OK libitb status.
  ! Every wrapper method funnels its non-OK return through this
  ! helper; only the free-function stream subroutines deviate by
  ! accepting an `intent(out) :: status` argument and returning the
  ! raw code to the caller instead of halting.
  subroutine raise_itb_error(status)
    use, intrinsic :: iso_fortran_env, only: error_unit
    integer(itb_status_kind), intent(in) :: status
    character(:), allocatable :: name, msg

    name = itb_status_to_string(status)
    msg  = itb_last_error_message()
    if (len(msg) > 0) then
      write (error_unit, "(A,I0,A,A,A,A,A)") &
        "itb: ", status, " (", name, "): ", msg, ""
    else
      write (error_unit, "(A,I0,A,A,A)") &
        "itb: ", status, " (", name, ")"
    end if
    error stop 1
  end subroutine

end module itb_errors
