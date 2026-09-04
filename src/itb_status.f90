! itb_status.f90 -- status codes returned by every libitb entry point.
!
! Mirrors the ITB_OK / ITB_ERR_* constants of the C ABI
! (cmd/cshared/internal/capi/errors.go). The numeric values are
! ABI-stable across releases; the label function is diagnostic only.

module itb_status
  use, intrinsic :: iso_c_binding, only: c_int
  implicit none
  private

  public :: itb_status_label

  integer(c_int), parameter, public :: ITB_STATUS_OK                   = 0
  integer(c_int), parameter, public :: ITB_STATUS_BAD_HASH             = 1
  integer(c_int), parameter, public :: ITB_STATUS_BAD_KEY_BITS         = 2
  integer(c_int), parameter, public :: ITB_STATUS_BAD_HANDLE           = 3
  integer(c_int), parameter, public :: ITB_STATUS_BAD_INPUT            = 4
  integer(c_int), parameter, public :: ITB_STATUS_BUFFER_TOO_SMALL     = 5
  integer(c_int), parameter, public :: ITB_STATUS_ENCRYPT_FAILED       = 6
  integer(c_int), parameter, public :: ITB_STATUS_DECRYPT_FAILED       = 7
  integer(c_int), parameter, public :: ITB_STATUS_SEED_WIDTH_MIX       = 8
  integer(c_int), parameter, public :: ITB_STATUS_BAD_MAC              = 9
  integer(c_int), parameter, public :: ITB_STATUS_MAC_FAILURE          = 10
  integer(c_int), parameter, public :: ITB_STATUS_BLOB_MALFORMED_RECIPE    = 11
  integer(c_int), parameter, public :: ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN = 12
  integer(c_int), parameter, public :: ITB_STATUS_UNKNOWN_PROFILE          = 13
  integer(c_int), parameter, public :: ITB_STATUS_BLOB_MODE_MISMATCH   = 19
  integer(c_int), parameter, public :: ITB_STATUS_BLOB_MALFORMED       = 20
  integer(c_int), parameter, public :: ITB_STATUS_BLOB_VERSION_TOO_NEW = 21
  integer(c_int), parameter, public :: ITB_STATUS_BLOB_TOO_MANY_OPTS   = 22
  integer(c_int), parameter, public :: ITB_STATUS_STREAM_TRUNCATED     = 23
  integer(c_int), parameter, public :: ITB_STATUS_STREAM_AFTER_FINAL   = 24
  integer(c_int), parameter, public :: ITB_STATUS_TRIPLE_CLOSED        = 25
  integer(c_int), parameter, public :: ITB_STATUS_PROFILE_EXISTS       = 26
  integer(c_int), parameter, public :: ITB_STATUS_INTERNAL             = 99

contains

  ! Short human-readable label for a status code.
  pure function itb_status_label(code) result(label)
    integer(c_int), intent(in) :: code
    character(:), allocatable  :: label

    select case (code)
    case (ITB_STATUS_OK);                   label = "ok"
    case (ITB_STATUS_BAD_HASH);             label = "unknown hash name"
    case (ITB_STATUS_BAD_KEY_BITS);         label = "invalid key bits"
    case (ITB_STATUS_BAD_HANDLE);           label = "invalid handle"
    case (ITB_STATUS_BAD_INPUT);            label = "invalid input"
    case (ITB_STATUS_BUFFER_TOO_SMALL);     label = "output buffer too small"
    case (ITB_STATUS_ENCRYPT_FAILED);       label = "encrypt failed"
    case (ITB_STATUS_DECRYPT_FAILED);       label = "decrypt failed"
    case (ITB_STATUS_SEED_WIDTH_MIX);       label = "seed width mismatch"
    case (ITB_STATUS_BAD_MAC);              label = "unknown MAC name or invalid MAC handle"
    case (ITB_STATUS_MAC_FAILURE);          label = "MAC verification failed"
    case (ITB_STATUS_BLOB_MALFORMED_RECIPE); label = "blob recipe malformed"
    case (ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN); label = "blob recipe names an unknown primitive"
    case (ITB_STATUS_UNKNOWN_PROFILE);      label = "unknown profile name"
    case (ITB_STATUS_BLOB_MODE_MISMATCH);   label = "blob mode mismatch"
    case (ITB_STATUS_BLOB_MALFORMED);       label = "malformed state blob"
    case (ITB_STATUS_BLOB_VERSION_TOO_NEW); label = "blob version too new"
    case (ITB_STATUS_BLOB_TOO_MANY_OPTS);   label = "too many blob options"
    case (ITB_STATUS_STREAM_TRUNCATED);     label = "stream transcript truncated"
    case (ITB_STATUS_STREAM_AFTER_FINAL);   label = "stream chunk after terminator"
    case (ITB_STATUS_TRIPLE_CLOSED);        label = "Triple Pipeline is closed"
    case (ITB_STATUS_PROFILE_EXISTS);       label = "profile name already registered"
    case (ITB_STATUS_INTERNAL);             label = "internal error"
    case default;                           label = "unknown status"
    end select
  end function

end module itb_status
