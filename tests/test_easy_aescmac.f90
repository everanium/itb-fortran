! test_easy_aescmac.f90 -- AES-CMAC Easy Mode encryptor coverage.
!
! Mirrors the C binding's test_easy_aescmac.c at the Easy Mode level.
! AES-CMAC is the W128 PRF-grade primitive in the ITB suite and ships
! at a single hash width (128, the AES block size). The test exercises
! Single Ouroboros + Triple Ouroboros construction via
! `new_itb_encryptor`, the read-only accessor surface, plain encrypt /
! decrypt round-trip, and authenticated encrypt / decrypt round-trip
! with a tampered-ciphertext rejection step.
!
! The high-level wrapper `enc%decrypt_auth(...)` raises on
! STATUS_MAC_FAILURE, so the tamper sub-test drops to the low-level
! FFI binding (`itb_easy_decrypt_auth_c`) to observe the explicit
! mac-failure status without terminating the test program.

program test_easy_aescmac
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_decrypt_auth_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_aescmac"
  character(*), parameter :: HASH_NAME = "aescmac"
  integer,      parameter :: KEY_BITS  = 1024
  integer,      parameter :: PT_LEN    = 256

  call test_single_mode()
  call test_triple_mode()
  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(n))
    do i = 1, n
      p(i) = int(iand(int(i - 1, c_int64_t) * 11_c_int64_t + 23_c_int64_t, &
                      255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_single_mode()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc
    integer(itb_int32_kind)  :: hsize
    integer :: i, end_b

    plaintext = pseudo_plaintext(PT_LEN)

    call new_itb_encryptor(enc, HASH_NAME, KEY_BITS, "hmac-blake3", 1)

    call assert_string_eq(TEST_NAME, "single primitive", enc%primitive(), HASH_NAME)
    call assert_int_eq(TEST_NAME, "single key_bits",   int(enc%key_bits()),   KEY_BITS)
    call assert_int_eq(TEST_NAME, "single mode",       int(enc%mode()),       1)
    call assert_string_eq(TEST_NAME, "single mac_name", enc%mac_name(), "hmac-blake3")
    call assert_int_eq(TEST_NAME, "single seed_count", int(enc%seed_count()), 3)
    call assert_true(TEST_NAME, "single nonce_bits > 0", enc%nonce_bits() > 0)
    call assert_true(TEST_NAME, "single header_size > 0", enc%header_size() > 0)
    call assert_true(TEST_NAME, "single has_prf_keys", enc%has_prf_keys())
    call assert_false(TEST_NAME, "single is_mixed", enc%is_mixed())

    ct = enc%encrypt(plaintext)
    pt = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "single plain roundtrip", pt, plaintext)

    ct = enc%encrypt_auth(plaintext)
    pt = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "single auth roundtrip", pt, plaintext)

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
    call assert_status_eq(TEST_NAME, "single tamper rejection", rc, STATUS_MAC_FAILURE)
    deallocate (scratch)

    call enc%destroy()
  end subroutine

  subroutine test_triple_mode()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc
    integer(itb_int32_kind)  :: hsize
    integer :: i, end_b

    plaintext = pseudo_plaintext(PT_LEN)

    call new_itb_encryptor(enc, HASH_NAME, KEY_BITS, "hmac-blake3", 3)

    call assert_int_eq(TEST_NAME, "triple mode",       int(enc%mode()),       3)
    call assert_int_eq(TEST_NAME, "triple seed_count", int(enc%seed_count()), 7)
    call assert_int_eq(TEST_NAME, "triple key_bits",   int(enc%key_bits()),   KEY_BITS)
    call assert_string_eq(TEST_NAME, "triple primitive", enc%primitive(), HASH_NAME)

    ct = enc%encrypt(plaintext)
    pt = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "triple plain roundtrip", pt, plaintext)

    ct = enc%encrypt_auth(plaintext)
    pt = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "triple auth roundtrip", pt, plaintext)

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
    call assert_status_eq(TEST_NAME, "triple tamper rejection", rc, STATUS_MAC_FAILURE)
    deallocate (scratch)

    call enc%destroy()
  end subroutine

end program test_easy_aescmac
