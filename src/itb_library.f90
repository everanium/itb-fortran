! itb_library.f90 -- library-level info + process-wide setters/getters.
!
! Wraps the libitb FFI surface that has no per-instance handle:
!
!   * `itb_version()`               -> NUL-stripped library version
!   * `itb_max_key_bits()`          -> max accepted ITB key width
!   * `itb_channels()`              -> ITB channels per byte (7)
!   * `itb_header_size()`           -> wire header byte length (process-wide)
!   * `itb_hash_count` / `itb_hash_name(i)` / `itb_hash_width(i)`
!   * `itb_mac_count`  / `itb_mac_name(i)` / `itb_mac_key_size(i)` /
!     `itb_mac_tag_size(i)` / `itb_mac_min_key_bytes(i)`
!   * `itb_set_*` / `itb_get_*` for `bit_soup`, `lock_soup`,
!     `max_workers`, `nonce_bits`, `barrier_fill`
!   * `itb_list_hashes()` / `itb_list_macs()` -> allocatable name array
!
! Process-wide setters are atomic individually (Go-side
! `atomic.Int32.Store`); the caveat is logical -- mid-encrypt mutation
! corrupts the running operation because the cipher snapshots its
! configuration at call entry. The wrappers do NOT pre-validate
! arguments beyond what type marshalling requires; libitb owns the
! cascade / coercion / validation logic on both Easy Mode and the
! low-level path.

module itb_library
  use itb_kinds
  use itb_sys
  use itb_strings, only: c_buffer_to_fortran_string, make_c_string
  use itb_errors,  only: STATUS_OK, STATUS_BUFFER_TOO_SMALL, raise_itb_error
  implicit none
  private

  public :: itb_version
  public :: itb_max_key_bits
  public :: itb_channels
  public :: itb_header_size

  public :: itb_hash_count
  public :: itb_hash_name
  public :: itb_hash_width
  public :: itb_list_hashes

  public :: itb_mac_count
  public :: itb_mac_name
  public :: itb_mac_key_size
  public :: itb_mac_tag_size
  public :: itb_mac_min_key_bytes
  public :: itb_list_macs

  public :: itb_set_bit_soup, itb_get_bit_soup
  public :: itb_set_lock_soup, itb_get_lock_soup
  public :: itb_set_max_workers, itb_get_max_workers
  public :: itb_set_nonce_bits, itb_get_nonce_bits
  public :: itb_set_barrier_fill, itb_get_barrier_fill

contains

  function itb_version() result(s)
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    out_len = 0_itb_size_kind
    rc = itb_version_c(c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_version_c(c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_max_key_bits() result(n)
    integer(itb_int32_kind) :: n
    n = itb_max_key_bits_c()
  end function

  function itb_channels() result(n)
    integer(itb_int32_kind) :: n
    n = itb_channels_c()
  end function

  function itb_header_size() result(n)
    integer(itb_int32_kind) :: n
    n = itb_header_size_c()
  end function

  function itb_hash_count() result(n)
    integer(itb_int32_kind) :: n
    n = itb_hash_count_c()
  end function

  function itb_hash_name(i) result(s)
    integer, intent(in) :: i
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    out_len = 0_itb_size_kind
    rc = itb_hash_name_c(int(i, c_int), c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_hash_name_c(int(i, c_int), c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_hash_width(i) result(w)
    integer, intent(in) :: i
    integer(itb_int32_kind) :: w
    w = itb_hash_width_c(int(i, c_int))
  end function

  ! Returns a list of every registered hash primitive name. Each entry
  ! is allocated independently and NUL-stripped per the binding's
  ! uniform string-getter discipline.
  function itb_list_hashes() result(names)
    character(len=:), allocatable :: names(:)
    integer(itb_int32_kind) :: n, i, max_len
    character(:), allocatable :: tmp

    n = itb_hash_count_c()
    if (n <= 0) then
      allocate (character(len=0) :: names(0))
      return
    end if

    ! Two-pass: first compute max length so the array can hold the
    ! widest name, then fill.
    max_len = 0
    do i = 1, n
      tmp = itb_hash_name(int(i - 1))
      if (len(tmp) > max_len) max_len = len(tmp)
    end do
    allocate (character(len=max_len) :: names(n))
    do i = 1, n
      tmp = itb_hash_name(int(i - 1))
      names(i)             = repeat(' ', max_len)
      names(i)(1:len(tmp)) = tmp
    end do
  end function

  function itb_mac_count() result(n)
    integer(itb_int32_kind) :: n
    n = itb_mac_count_c()
  end function

  function itb_mac_name(i) result(s)
    integer, intent(in) :: i
    character(:), allocatable :: s
    character(kind=c_char), allocatable, target :: buf(:)
    integer(itb_size_kind) :: cap, out_len
    integer(itb_status_kind) :: rc

    out_len = 0_itb_size_kind
    rc = itb_mac_name_c(int(i, c_int), c_null_ptr, 0_itb_size_kind, out_len)
    if (rc /= STATUS_OK .and. rc /= STATUS_BUFFER_TOO_SMALL) call raise_itb_error(rc)

    cap = max(out_len + 1_itb_size_kind, 64_itb_size_kind)
    allocate (buf(cap))
    rc = itb_mac_name_c(int(i, c_int), c_loc(buf), cap, out_len)
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    call c_buffer_to_fortran_string(buf, out_len, s)
  end function

  function itb_mac_key_size(i) result(n)
    integer, intent(in) :: i
    integer(itb_int32_kind) :: n
    n = itb_mac_key_size_c(int(i, c_int))
  end function

  function itb_mac_tag_size(i) result(n)
    integer, intent(in) :: i
    integer(itb_int32_kind) :: n
    n = itb_mac_tag_size_c(int(i, c_int))
  end function

  function itb_mac_min_key_bytes(i) result(n)
    integer, intent(in) :: i
    integer(itb_int32_kind) :: n
    n = itb_mac_min_key_bytes_c(int(i, c_int))
  end function

  function itb_list_macs() result(names)
    character(len=:), allocatable :: names(:)
    integer(itb_int32_kind) :: n, i, max_len
    character(:), allocatable :: tmp

    n = itb_mac_count_c()
    if (n <= 0) then
      allocate (character(len=0) :: names(0))
      return
    end if
    max_len = 0
    do i = 1, n
      tmp = itb_mac_name(int(i - 1))
      if (len(tmp) > max_len) max_len = len(tmp)
    end do
    allocate (character(len=max_len) :: names(n))
    do i = 1, n
      tmp = itb_mac_name(int(i - 1))
      names(i)             = repeat(' ', max_len)
      names(i)(1:len(tmp)) = tmp
    end do
  end function

  ! Process-wide setters / getters. Setters surface non-OK status via
  ! raise; getters return the current value with no fallible path
  ! (libitb implements them as pure atomic loads).

  subroutine itb_set_bit_soup(mode)
    integer, intent(in) :: mode
    integer(itb_status_kind) :: rc
    rc = itb_set_bit_soup_c(int(mode, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  function itb_get_bit_soup() result(mode)
    integer(itb_int32_kind) :: mode
    mode = itb_get_bit_soup_c()
  end function

  subroutine itb_set_lock_soup(mode)
    integer, intent(in) :: mode
    integer(itb_status_kind) :: rc
    rc = itb_set_lock_soup_c(int(mode, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  function itb_get_lock_soup() result(mode)
    integer(itb_int32_kind) :: mode
    mode = itb_get_lock_soup_c()
  end function

  subroutine itb_set_max_workers(n)
    integer, intent(in) :: n
    integer(itb_status_kind) :: rc
    rc = itb_set_max_workers_c(int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  function itb_get_max_workers() result(n)
    integer(itb_int32_kind) :: n
    n = itb_get_max_workers_c()
  end function

  subroutine itb_set_nonce_bits(n)
    integer, intent(in) :: n
    integer(itb_status_kind) :: rc
    rc = itb_set_nonce_bits_c(int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  function itb_get_nonce_bits() result(n)
    integer(itb_int32_kind) :: n
    n = itb_get_nonce_bits_c()
  end function

  subroutine itb_set_barrier_fill(n)
    integer, intent(in) :: n
    integer(itb_status_kind) :: rc
    rc = itb_set_barrier_fill_c(int(n, c_int))
    if (rc /= STATUS_OK) call raise_itb_error(rc)
  end subroutine

  function itb_get_barrier_fill() result(n)
    integer(itb_int32_kind) :: n
    n = itb_get_barrier_fill_c()
  end function

end module itb_library
