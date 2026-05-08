! test_easy_nonce_sizes.f90 -- round-trip tests across every per-
! instance nonce-size configuration on the high-level Easy Mode
! encryptor surface.
!
! Mirrors the C binding's test_easy_nonce_sizes.c one-to-one.
! enc%set_nonce_bits is per-instance and does not touch the process-
! global itb_set_nonce_bits / itb_get_nonce_bits accessors; each
! encryptor's enc%header_size and enc%parse_chunk_len track its own
! nonce_bits state. None of the tests in this file mutate process-
! global state.
!
! Per-binary process isolation gives this test its own libitb global
! state, so no in-process serial lock is required.

program test_easy_nonce_sizes
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_decrypt_auth_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_nonce_sizes"
  integer,      parameter :: PT_LEN    = 1024
  integer,      parameter :: NONCE_SIZES(3) = [128, 256, 512]
  character(len=11), parameter :: MACS(3) = &
      [character(len=11) :: "kmac256", "hmac-sha256", "hmac-blake3"]
  character(len=10), parameter :: HASHES(3) = &
      [character(len=10) :: "siphash24", "blake3", "blake2b512"]

  call test_header_size_default_is_20()
  call test_header_size_dynamic()
  call test_encrypt_decrypt_across_single()
  call test_encrypt_decrypt_across_triple()
  call test_auth_across_single()
  call test_auth_across_triple()
  call test_two_encryptors_independent_nonce_bits()

  call test_pass(TEST_NAME)

contains

  function pseudo_plaintext(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 29_c_int64_t + 13_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_header_size_default_is_20()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call assert_int_eq(TEST_NAME, "default nonce_bits",  &
                        int(enc%nonce_bits()),  128)
    call assert_int_eq(TEST_NAME, "default header_size", &
                        int(enc%header_size()), 20)
    call enc%destroy()
  end subroutine

  subroutine test_header_size_dynamic()
    type(itb_encryptor_t) :: enc
    integer :: i

    do i = 1, size(NONCE_SIZES)
      call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
      call enc%set_nonce_bits(NONCE_SIZES(i))
      call assert_int_eq(TEST_NAME, "nonce_bits set", &
                          int(enc%nonce_bits()),  NONCE_SIZES(i))
      call assert_int_eq(TEST_NAME, "header_size = nb/8 + 4", &
                          int(enc%header_size()), NONCE_SIZES(i) / 8 + 4)
      call enc%destroy()
    end do
  end subroutine

  subroutine test_encrypt_decrypt_across_single()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: header(:)
    integer(itb_size_kind) :: parsed
    integer(itb_int32_kind) :: hs
    integer :: i, h, j

    plaintext = pseudo_plaintext(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do h = 1, size(HASHES)
        call new_itb_encryptor(enc, trim(HASHES(h)), 1024, "kmac256", 1)
        call enc%set_nonce_bits(NONCE_SIZES(i))

        ct = enc%encrypt(plaintext)
        pt = enc%decrypt(ct)
        call assert_bytes_eq(TEST_NAME, "single roundtrip", pt, plaintext)

        hs = enc%header_size()
        if (allocated(header)) deallocate (header)
        allocate (header(int(hs)))
        do j = 1, int(hs)
          header(j) = ct(j)
        end do
        parsed = enc%parse_chunk_len(header)
        call assert_size_eq(TEST_NAME, "parse_chunk_len matches", &
                             parsed, int(size(ct), itb_size_kind))

        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine test_encrypt_decrypt_across_triple()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: header(:)
    integer(itb_size_kind) :: parsed
    integer(itb_int32_kind) :: hs
    integer :: i, h, j

    plaintext = pseudo_plaintext(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do h = 1, size(HASHES)
        call new_itb_encryptor(enc, trim(HASHES(h)), 1024, "kmac256", 3)
        call enc%set_nonce_bits(NONCE_SIZES(i))

        ct = enc%encrypt(plaintext)
        pt = enc%decrypt(ct)
        call assert_bytes_eq(TEST_NAME, "triple roundtrip", pt, plaintext)

        hs = enc%header_size()
        if (allocated(header)) deallocate (header)
        allocate (header(int(hs)))
        do j = 1, int(hs)
          header(j) = ct(j)
        end do
        parsed = enc%parse_chunk_len(header)
        call assert_size_eq(TEST_NAME, "parse_chunk_len triple matches", &
                             parsed, int(size(ct), itb_size_kind))

        call enc%destroy()
      end do
    end do
  end subroutine

  subroutine auth_roundtrip_at(mode_value)
    integer, intent(in) :: mode_value
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_int32_kind) :: hs
    integer(itb_size_kind)  :: out_len
    integer(itb_status_kind) :: rc
    integer :: i, m, j, end_b

    plaintext = pseudo_plaintext(PT_LEN)
    do i = 1, size(NONCE_SIZES)
      do m = 1, size(MACS)
        call new_itb_encryptor(enc, "blake3", 1024, trim(MACS(m)), mode_value)
        call enc%set_nonce_bits(NONCE_SIZES(i))

        ct = enc%encrypt_auth(plaintext)
        pt = enc%decrypt_auth(ct)
        call assert_bytes_eq(TEST_NAME, "auth roundtrip", pt, plaintext)

        ! Tamper inside the structured payload past the dynamic header.
        hs = enc%header_size()
        end_b = int(hs) + 256
        if (end_b > size(ct)) end_b = size(ct)
        do j = int(hs) + 1, end_b
          ct(j) = ieor(ct(j), 1_itb_byte_kind)
        end do
        if (allocated(scratch)) deallocate (scratch)
        allocate (scratch(size(ct) + 64))
        out_len = 0_itb_size_kind
        rc = itb_easy_decrypt_auth_c(enc%raw_handle(),                            &
                                      c_loc(ct),       int(size(ct),      itb_size_kind), &
                                      c_loc(scratch),  int(size(scratch), itb_size_kind), &
                                      out_len)
        call assert_status_eq(TEST_NAME, "auth tamper rejection", &
                               rc, STATUS_MAC_FAILURE)

        call enc%destroy()
      end do
    end do
    if (allocated(scratch)) deallocate (scratch)
  end subroutine

  subroutine test_auth_across_single()
    call auth_roundtrip_at(1)
  end subroutine

  subroutine test_auth_across_triple()
    call auth_roundtrip_at(3)
  end subroutine

  subroutine test_two_encryptors_independent_nonce_bits()
    type(itb_encryptor_t) :: a, b
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct_a(:), ct_b(:)
    integer(itb_byte_kind), allocatable :: pt_a(:), pt_b(:)
    character(*), parameter :: PT_TEXT = "isolation test"
    integer :: i

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_encryptor(a, "blake3", 1024, "kmac256", 1)
    call new_itb_encryptor(b, "blake3", 1024, "kmac256", 1)
    call a%set_nonce_bits(512)

    call assert_int_eq(TEST_NAME, "a nonce_bits",  int(a%nonce_bits()),  512)
    call assert_int_eq(TEST_NAME, "a header_size", int(a%header_size()), 68)
    call assert_int_eq(TEST_NAME, "b nonce_bits stays default", &
                        int(b%nonce_bits()),  128)
    call assert_int_eq(TEST_NAME, "b header_size stays default", &
                        int(b%header_size()), 20)

    ct_a = a%encrypt(pt_in)
    pt_a = a%decrypt(ct_a)
    call assert_bytes_eq(TEST_NAME, "a roundtrip", pt_a, pt_in)

    ct_b = b%encrypt(pt_in)
    pt_b = b%decrypt(ct_b)
    call assert_bytes_eq(TEST_NAME, "b roundtrip", pt_b, pt_in)

    call a%destroy()
    call b%destroy()
  end subroutine

end program test_easy_nonce_sizes
