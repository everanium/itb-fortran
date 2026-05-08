! test_easy_areion.f90 -- Areion-SoEM Easy Mode encryptor coverage.
!
! Mirrors the C binding's test_easy_areion.c at the Easy Mode level.
! The Areion-SoEM family ships at two hash widths -- areion256 (W256)
! and areion512 (W512); both are exercised here. Each width is
! constructed via `new_itb_encryptor` in Single Ouroboros and Triple
! Ouroboros, then put through the read-only accessor surface, plain
! encrypt / decrypt, and authenticated encrypt / decrypt with a
! tamper-rejection step.
!
! The high-level wrapper `enc%decrypt_auth(...)` raises on
! STATUS_MAC_FAILURE, so the tamper sub-test drops to the low-level
! FFI binding (`itb_easy_decrypt_auth_c`) to observe the explicit
! mac-failure status without terminating the test program.

program test_easy_areion
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_decrypt_auth_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_areion"
  integer,      parameter :: KEY_BITS  = 1024
  integer,      parameter :: PT_LEN    = 256
  character(len=9), parameter :: HASH_NAMES(2) = &
                          [character(len=9) :: "areion256", "areion512"]

  integer :: hi

  do hi = 1, size(HASH_NAMES)
    call test_single_mode(trim(HASH_NAMES(hi)))
    call test_triple_mode(trim(HASH_NAMES(hi)))
  end do

  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(n))
    do i = 1, n
      p(i) = int(iand(int(i - 1, c_int64_t) * 13_c_int64_t + 29_c_int64_t, &
                      255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_single_mode(hash_name)
    character(*), intent(in) :: hash_name
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

    call new_itb_encryptor(enc, hash_name, KEY_BITS, "hmac-blake3", 1)

    call assert_string_eq(TEST_NAME, hash_name // " single primitive", &
                           enc%primitive(), hash_name)
    call assert_int_eq(TEST_NAME, hash_name // " single key_bits", &
                        int(enc%key_bits()), KEY_BITS)
    call assert_int_eq(TEST_NAME, hash_name // " single mode", &
                        int(enc%mode()), 1)
    call assert_string_eq(TEST_NAME, hash_name // " single mac_name", &
                           enc%mac_name(), "hmac-blake3")
    call assert_int_eq(TEST_NAME, hash_name // " single seed_count", &
                        int(enc%seed_count()), 3)
    call assert_true(TEST_NAME, hash_name // " single nonce_bits > 0", &
                      enc%nonce_bits() > 0)
    call assert_true(TEST_NAME, hash_name // " single header_size > 0", &
                      enc%header_size() > 0)
    call assert_true(TEST_NAME, hash_name // " single has_prf_keys", &
                      enc%has_prf_keys())
    call assert_false(TEST_NAME, hash_name // " single is_mixed", enc%is_mixed())

    ct = enc%encrypt(plaintext)
    pt = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, hash_name // " single plain roundtrip", &
                          pt, plaintext)

    ct = enc%encrypt_auth(plaintext)
    pt = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, hash_name // " single auth roundtrip", &
                          pt, plaintext)

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
    call assert_status_eq(TEST_NAME, hash_name // " single tamper rejection", &
                           rc, STATUS_MAC_FAILURE)
    deallocate (scratch)

    call enc%destroy()
  end subroutine

  subroutine test_triple_mode(hash_name)
    character(*), intent(in) :: hash_name
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

    call new_itb_encryptor(enc, hash_name, KEY_BITS, "hmac-blake3", 3)

    call assert_int_eq(TEST_NAME, hash_name // " triple mode", &
                        int(enc%mode()), 3)
    call assert_int_eq(TEST_NAME, hash_name // " triple seed_count", &
                        int(enc%seed_count()), 7)
    call assert_int_eq(TEST_NAME, hash_name // " triple key_bits", &
                        int(enc%key_bits()), KEY_BITS)
    call assert_string_eq(TEST_NAME, hash_name // " triple primitive", &
                           enc%primitive(), hash_name)

    ct = enc%encrypt(plaintext)
    pt = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, hash_name // " triple plain roundtrip", &
                          pt, plaintext)

    ct = enc%encrypt_auth(plaintext)
    pt = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, hash_name // " triple auth roundtrip", &
                          pt, plaintext)

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
    call assert_status_eq(TEST_NAME, hash_name // " triple tamper rejection", &
                           rc, STATUS_MAC_FAILURE)
    deallocate (scratch)

    call enc%destroy()
  end subroutine

end program test_easy_areion
