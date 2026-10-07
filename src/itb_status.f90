! Status codes returned by every libitb3 entry point.
!
! Mirrors the ITB_OK / ITB_ERR_* constants of the C ABI
! (cmd/cshared/internal/capi/errors.go). The numeric values are
! ABI-stable across releases.

module itb_status
  use, intrinsic :: iso_c_binding, only: c_int
  implicit none
  private

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

end module itb_status
