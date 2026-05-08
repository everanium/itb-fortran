! test_easy_auth.f90 -- authenticated encryption coverage on the
! high-level Easy Mode encryptor surface.
!
! Mirrors the C binding's test_easy_auth.c one-to-one. Same matrix
! (3 MACs x 3 hash widths x {Single, Triple} round-trip plus tamper
! rejection); cross-MAC structural rejection rides through the
! enc%export_state() / enc%import_state() path with
! itb_last_mismatch_field() reporting "mac"; same-primitive
! different-key MAC failure verifies that two independently-
! constructed encryptors collide on STATUS_MAC_FAILURE rather than
! yielding corrupted plaintext.
!
! The high-level wrapper `enc%decrypt_auth(...)` raises on
! STATUS_MAC_FAILURE / STATUS_EASY_MISMATCH, so the rejection sub-
! tests drop to the low-level FFI bindings (`itb_easy_decrypt_auth_c`
! / `itb_easy_import_c`) to observe the explicit status without
! terminating the test program.

program test_easy_auth
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_decrypt_auth_c, itb_easy_import_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_auth"
  integer,      parameter :: PT_LEN    = 4096

  call test_all_macs_all_widths_single()
  call test_all_macs_all_widths_triple()
  call test_cross_mac_rejection_different_primitive()
  call test_same_primitive_different_key_mac_failure()

  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 19_c_int64_t + 7_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine roundtrip_with(prim_name, mac_name, mode, plaintext)
    character(*),                                  intent(in) :: prim_name, mac_name
    integer,                                        intent(in) :: mode
    integer(itb_byte_kind), target,                 intent(in) :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc
    integer(itb_int32_kind)  :: hsize
    integer :: i, end_b

    call new_itb_encryptor(enc, prim_name, 1024, mac_name, mode)

    ct = enc%encrypt_auth(plaintext)
    pt = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "auth roundtrip", pt, plaintext)

    ! Tamper inside the structured payload (256 bytes past the dynamic
    ! header). MAC verification must reject.
    hsize = enc%header_size()
    end_b = int(hsize) + 256
    if (end_b > size(ct)) end_b = size(ct)
    do i = int(hsize) + 1, end_b
      ct(i) = ieor(ct(i), 1_itb_byte_kind)
    end do
    allocate (scratch(size(ct) + 64))
    out_len = 0_itb_size_kind
    rc = itb_easy_decrypt_auth_c(enc%raw_handle(),                            &
                                  c_loc(ct),       int(size(ct),      itb_size_kind), &
                                  c_loc(scratch),  int(size(scratch), itb_size_kind), &
                                  out_len)
    call assert_status_eq(TEST_NAME, "tamper rejection", rc, STATUS_MAC_FAILURE)
    deallocate (scratch)

    call enc%destroy()
  end subroutine

  subroutine test_all_macs_all_widths_single()
    character(len=11), parameter :: MACS(3) = &
        [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    character(len=10), parameter :: HASHES(3) = &
        [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer :: m, h

    plaintext = pseudo_plaintext(PT_LEN)
    do m = 1, size(MACS)
      do h = 1, size(HASHES)
        call roundtrip_with(trim(HASHES(h)), trim(MACS(m)), 1, plaintext)
      end do
    end do
  end subroutine

  subroutine test_all_macs_all_widths_triple()
    character(len=11), parameter :: MACS(3) = &
        [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
    character(len=10), parameter :: HASHES(3) = &
        [character(len=10) :: "siphash24", "blake3", "blake2b512"]
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer :: m, h

    plaintext = pseudo_plaintext(PT_LEN)
    do m = 1, size(MACS)
      do h = 1, size(HASHES)
        call roundtrip_with(trim(HASHES(h)), trim(MACS(m)), 3, plaintext)
      end do
    end do
  end subroutine

  subroutine test_cross_mac_rejection_different_primitive()
    ! Sender uses kmac256; receiver builds a fresh blake3 / 1024 /
    ! hmac-sha256 / Single encryptor and Imports the kmac256 blob.
    ! The Import path must reject with STATUS_EASY_MISMATCH and
    ! itb_last_mismatch_field() must report "mac".
    type(itb_encryptor_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_size_kind)   :: blob_len
    integer(itb_status_kind) :: rc
    character(:), allocatable :: field

    call new_itb_encryptor(src, "blake3", 1024, "kmac256", 1)
    blob = src%export_state()
    call src%destroy()

    call new_itb_encryptor(dst, "blake3", 1024, "hmac-sha256", 1)
    blob_len = int(size(blob), itb_size_kind)
    rc = itb_easy_import_c(dst%raw_handle(), c_loc(blob), blob_len)
    call assert_status_eq(TEST_NAME, "cross-mac rejected", rc, STATUS_EASY_MISMATCH)

    field = itb_last_mismatch_field()
    call assert_string_eq(TEST_NAME, "mismatch field", field, "mac")

    call dst%destroy()
  end subroutine

  subroutine test_same_primitive_different_key_mac_failure()
    ! Day 1: encrypt with enc1's seeds + MAC key. Day 2: enc2 has
    ! its own (different) seed and MAC keys; decrypt must fail with
    ! STATUS_MAC_FAILURE rather than yielding corrupted plaintext.
    type(itb_encryptor_t) :: enc1, enc2
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc
    character(*), parameter :: PT_TEXT = "authenticated payload"
    integer :: i

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_encryptor(enc1, "blake3", 1024, "hmac-sha256", 1)
    call new_itb_encryptor(enc2, "blake3", 1024, "hmac-sha256", 1)

    ct = enc1%encrypt_auth(plaintext)

    allocate (scratch(size(ct) + 64))
    out_len = 0_itb_size_kind
    rc = itb_easy_decrypt_auth_c(enc2%raw_handle(),                          &
                                  c_loc(ct),       int(size(ct),      itb_size_kind), &
                                  c_loc(scratch),  int(size(scratch), itb_size_kind), &
                                  out_len)
    call assert_status_eq(TEST_NAME, "different key rejected", rc, STATUS_MAC_FAILURE)

    call enc1%destroy()
    call enc2%destroy()
  end subroutine

end program test_easy_auth
