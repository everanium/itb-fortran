! test_auth.f90 -- end-to-end authenticated-encryption coverage.
!
! Exercises the 3 MACs x 3 hash widths x {Single, Triple} round-trip
! plus tamper rejection at the dynamic header offset and cross-MAC
! rejection. The MAC registry probe verifies the canonical (name,
! key_size, tag_size, min_key_bytes) tuples surfaced by libitb match
! the cross-binding contract.
!
! The high-level `itb_decrypt_auth` / `itb_decrypt_auth_triple`
! wrappers raise on any non-OK libitb status. The tamper / cross-MAC
! sub-tests therefore drop to the low-level FFI binding
! (`itb_decrypt_auth_c` / `itb_decrypt_auth3_c` from `itb_sys`) so
! the explicit STATUS_MAC_FAILURE branch can be observed without
! terminating the test program.

program test_auth
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_decrypt_auth_c, itb_decrypt_auth3_c, itb_new_mac_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_auth"

  call test_list_macs()
  call test_create_and_free()
  call test_mac_free_release()
  call test_bad_name()
  call test_short_key()
  call test_roundtrip_all_macs_all_widths()
  call test_triple_roundtrip_all_macs_all_widths()
  call test_cross_mac_different_primitive()
  call test_cross_mac_same_primitive_different_key()

  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(n))
    do i = 1, n
      p(i) = int(iand(int(i - 1, c_int64_t), 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_list_macs()
    integer(itb_int32_kind) :: count
    character(:), allocatable :: name
    integer :: idx, expected_count

    expected_count = 3
    count = itb_mac_count()
    call assert_int_eq(TEST_NAME, "mac_count", int(count), expected_count)

    name = itb_mac_name(0)
    call assert_string_eq(TEST_NAME, "mac_name(0)", name, "kmac256")
    call assert_int_eq(TEST_NAME, "mac_key_size(0)",      int(itb_mac_key_size(0)),      32)
    call assert_int_eq(TEST_NAME, "mac_tag_size(0)",      int(itb_mac_tag_size(0)),      32)
    call assert_int_eq(TEST_NAME, "mac_min_key_bytes(0)", int(itb_mac_min_key_bytes(0)), 16)

    name = itb_mac_name(1)
    call assert_string_eq(TEST_NAME, "mac_name(1)", name, "hmac-sha256")
    call assert_int_eq(TEST_NAME, "mac_key_size(1)",      int(itb_mac_key_size(1)),      32)
    call assert_int_eq(TEST_NAME, "mac_tag_size(1)",      int(itb_mac_tag_size(1)),      32)
    call assert_int_eq(TEST_NAME, "mac_min_key_bytes(1)", int(itb_mac_min_key_bytes(1)), 16)

    name = itb_mac_name(2)
    call assert_string_eq(TEST_NAME, "mac_name(2)", name, "hmac-blake3")
    call assert_int_eq(TEST_NAME, "mac_key_size(2)",      int(itb_mac_key_size(2)),      32)
    call assert_int_eq(TEST_NAME, "mac_tag_size(2)",      int(itb_mac_tag_size(2)),      32)
    call assert_int_eq(TEST_NAME, "mac_min_key_bytes(2)", int(itb_mac_min_key_bytes(2)), 32)
    idx = 0
  end subroutine

  subroutine test_create_and_free()
    integer(itb_byte_kind), target :: key(32)
    type(itb_mac_t) :: m
    character(len=11), parameter :: NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    integer :: i

    key(:) = 66_itb_byte_kind  ! 0x42
    do i = 1, size(NAMES)
      call new_itb_mac(m, trim(NAMES(i)), key)
      call assert_false(TEST_NAME, "mac handle live", m%is_closed())
      call m%destroy()
    end do
  end subroutine

  subroutine test_mac_free_release()
    integer(itb_byte_kind), target :: key(32)
    type(itb_mac_t) :: m
    integer :: i

    key(:) = 66_itb_byte_kind
    do i = 1, 32
      call new_itb_mac(m, "hmac-sha256", key)
      call m%destroy()
      ! Idempotent destroy.
      call m%destroy()
    end do
  end subroutine

  subroutine test_bad_name()
    integer(itb_byte_kind), target :: key(32)
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), target :: cname(13)
    character(*), parameter :: NAME = "nonsense-mac"
    integer :: i

    key(:) = 66_itb_byte_kind
    do i = 1, len(NAME)
      cname(i) = NAME(i:i)
    end do
    cname(len(NAME) + 1) = c_null_char

    handle = itb_null_handle
    rc = itb_new_mac_c(c_loc(cname), c_loc(key), int(size(key), itb_size_kind), handle)
    call assert_status_eq(TEST_NAME, "bad mac name rejected", rc, STATUS_BAD_MAC)
  end subroutine

  subroutine test_short_key()
    ! Each MAC has a min-key-bytes lower bound; passing a key one
    ! shorter than that lower bound must surface STATUS_BAD_INPUT.
    character(len=11), parameter :: NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    integer, parameter :: MIN_BYTES(3) = [16, 16, 32]
    integer(itb_byte_kind), allocatable, target :: short_key(:)
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: cname(:)
    integer :: i, j, short_len

    do i = 1, size(NAMES)
      short_len = MIN_BYTES(i) - 1
      if (allocated(short_key)) deallocate (short_key)
      allocate (short_key(short_len))
      short_key(:) = 17_itb_byte_kind
      if (allocated(cname)) deallocate (cname)
      allocate (cname(len_trim(NAMES(i)) + 1))
      do j = 1, len_trim(NAMES(i))
        cname(j) = NAMES(i)(j:j)
      end do
      cname(len_trim(NAMES(i)) + 1) = c_null_char
      handle = itb_null_handle
      rc = itb_new_mac_c(c_loc(cname), c_loc(short_key), &
                          int(short_len, itb_size_kind), handle)
      call assert_status_eq(TEST_NAME, "short key rejected", rc, STATUS_BAD_INPUT)
    end do
  end subroutine

  subroutine test_roundtrip_all_macs_all_widths()
    character(len=11), parameter :: MAC_NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    character(len=10), parameter :: HASHES(3) = &
                          [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer, parameter :: PT_LEN = 4096
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), target,     allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: mac
    integer :: mi, hi, b, end_b
    integer(itb_int32_kind)  :: hsize
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc

    plaintext = pseudo_plaintext(PT_LEN)
    key(:) = 66_itb_byte_kind

    do mi = 1, size(MAC_NAMES)
      do hi = 1, size(HASHES)
        call new_itb_mac(mac, trim(MAC_NAMES(mi)), key)
        call new_itb_seed(ns, trim(HASHES(hi)), 1024)
        call new_itb_seed(ds, trim(HASHES(hi)), 1024)
        call new_itb_seed(ss, trim(HASHES(hi)), 1024)

        ct = itb_encrypt_auth(ns, ds, ss, mac, plaintext)
        pt = itb_decrypt_auth(ns, ds, ss, mac, ct)
        call assert_bytes_eq(TEST_NAME, "single auth roundtrip", pt, plaintext)

        ! Tamper inside the dynamic header region.
        hsize = itb_header_size()
        end_b = int(hsize) + 256
        if (end_b > size(ct)) end_b = size(ct)
        if (allocated(tampered)) deallocate (tampered)
        allocate (tampered(size(ct)))
        tampered(:) = ct(:)
        do b = int(hsize) + 1, end_b
          tampered(b) = ieor(tampered(b), 1_itb_byte_kind)
        end do
        out_len = 0_itb_size_kind
        rc = itb_decrypt_auth_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                                 mac%raw_handle(), c_loc(tampered),                 &
                                 int(size(tampered), itb_size_kind),                &
                                 c_null_ptr, 0_itb_size_kind, out_len)
        call assert_status_eq(TEST_NAME, "tamper rejected", rc, STATUS_MAC_FAILURE)

        call ns%destroy(); call ds%destroy(); call ss%destroy()
        call mac%destroy()
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

  subroutine test_triple_roundtrip_all_macs_all_widths()
    character(len=11), parameter :: MAC_NAMES(3) = &
                          [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    character(len=10), parameter :: HASHES(3) = &
                          [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer, parameter :: PT_LEN = 4096
    integer(itb_byte_kind), target,     allocatable :: plaintext(:)
    integer(itb_byte_kind), target,     allocatable :: tampered(:)
    integer(itb_byte_kind), target              :: key(32)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, d1, d2, d3, st1, st2, st3
    type(itb_mac_t)  :: mac
    integer :: mi, hi, b, end_b
    integer(itb_int32_kind)  :: hsize
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc

    plaintext = pseudo_plaintext(PT_LEN)
    key(:) = 66_itb_byte_kind

    do mi = 1, size(MAC_NAMES)
      do hi = 1, size(HASHES)
        call new_itb_mac(mac, trim(MAC_NAMES(mi)), key)
        call new_itb_seed(ns,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d1,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d2,  trim(HASHES(hi)), 1024)
        call new_itb_seed(d3,  trim(HASHES(hi)), 1024)
        call new_itb_seed(st1, trim(HASHES(hi)), 1024)
        call new_itb_seed(st2, trim(HASHES(hi)), 1024)
        call new_itb_seed(st3, trim(HASHES(hi)), 1024)

        ct = itb_encrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, plaintext)
        pt = itb_decrypt_auth_triple(ns, d1, d2, d3, st1, st2, st3, mac, ct)
        call assert_bytes_eq(TEST_NAME, "triple auth roundtrip", pt, plaintext)

        hsize = itb_header_size()
        end_b = int(hsize) + 256
        if (end_b > size(ct)) end_b = size(ct)
        if (allocated(tampered)) deallocate (tampered)
        allocate (tampered(size(ct)))
        tampered(:) = ct(:)
        do b = int(hsize) + 1, end_b
          tampered(b) = ieor(tampered(b), 1_itb_byte_kind)
        end do
        out_len = 0_itb_size_kind
        rc = itb_decrypt_auth3_c(ns%raw_handle(),                               &
                                  d1%raw_handle(),  d2%raw_handle(),  d3%raw_handle(), &
                                  st1%raw_handle(), st2%raw_handle(), st3%raw_handle(),&
                                  mac%raw_handle(), c_loc(tampered),                 &
                                  int(size(tampered), itb_size_kind),                &
                                  c_null_ptr, 0_itb_size_kind, out_len)
        call assert_status_eq(TEST_NAME, "triple tamper rejected", rc, STATUS_MAC_FAILURE)

        call ns%destroy()
        call d1%destroy();  call d2%destroy();  call d3%destroy()
        call st1%destroy(); call st2%destroy(); call st3%destroy()
        call mac%destroy()
      end do
    end do
    if (allocated(tampered)) deallocate (tampered)
  end subroutine

  subroutine test_cross_mac_different_primitive()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: enc_mac, dec_mac
    integer(itb_byte_kind), target :: key(32)
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_size_kind) :: out_len
    integer(itb_status_kind) :: rc
    character(*), parameter :: PT_TEXT = "authenticated payload"
    integer :: i

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)

    key(:) = 66_itb_byte_kind
    call new_itb_mac(enc_mac, "kmac256",     key)
    call new_itb_mac(dec_mac, "hmac-sha256", key)

    ct = itb_encrypt_auth(ns, ds, ss, enc_mac, plaintext)
    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                             dec_mac%raw_handle(), c_loc(ct),                  &
                             int(size(ct), itb_size_kind),                     &
                             c_null_ptr, 0_itb_size_kind, out_len)
    call assert_status_eq(TEST_NAME, "cross-mac primitive rejected", &
                           rc, STATUS_MAC_FAILURE)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call enc_mac%destroy(); call dec_mac%destroy()
  end subroutine

  subroutine test_cross_mac_same_primitive_different_key()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_mac_t)  :: enc_mac, dec_mac
    integer(itb_byte_kind), target :: key_a(32), key_b(32)
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_size_kind) :: out_len
    integer(itb_status_kind) :: rc
    character(*), parameter :: PT_TEXT = "authenticated payload"
    integer :: i

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    key_a(:) = 1_itb_byte_kind
    key_b(:) = 2_itb_byte_kind

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)

    call new_itb_mac(enc_mac, "hmac-sha256", key_a)
    call new_itb_mac(dec_mac, "hmac-sha256", key_b)

    ct = itb_encrypt_auth(ns, ds, ss, enc_mac, plaintext)
    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                             dec_mac%raw_handle(), c_loc(ct),                  &
                             int(size(ct), itb_size_kind),                     &
                             c_null_ptr, 0_itb_size_kind, out_len)
    call assert_status_eq(TEST_NAME, "cross-mac key rejected", &
                           rc, STATUS_MAC_FAILURE)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call enc_mac%destroy(); call dec_mac%destroy()
  end subroutine

end program test_auth
