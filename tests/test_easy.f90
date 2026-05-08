! test_easy.f90 -- high-level Easy Mode encryptor smoke coverage.
!
! Mirrors the C binding's test_easy.c one-to-one. Confirms the
! Encryptor surface round-trips plaintext under Single + Triple
! Ouroboros, authenticates on tampered ciphertext, survives the
! export / import cycle on a fresh encryptor, and exposes the
! read-only field accessors with the correct values.
!
! Per-binary process isolation (one binary per tests/test_*.f90 file)
! gives every test a fresh libitb global state without an in-process
! serial lock.
!
! The high-level wrapper `enc%decrypt_auth(...)` raises on
! STATUS_MAC_FAILURE, so the tamper sub-test drops to the low-level
! FFI binding (`itb_easy_decrypt_auth_c`) to observe the explicit
! mac-failure status without terminating the test program.

program test_easy
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_decrypt_auth_c, itb_easy_new_c
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy"
  character(*), parameter :: PT_TEXT   = &
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit."

  call test_single_roundtrip_blake3_kmac256()
  call test_triple_roundtrip_areion512_kmac256()
  call test_auth_roundtrip_single()
  call test_auth_decrypt_tampered_fails_with_mac_failure()
  call test_export_import_roundtrip()
  call test_peek_config_returns_correct_tuple()
  call test_mixed_single_three_same_width_primitives()
  call test_invalid_mode_rejected()
  call test_close_is_idempotent()
  call test_header_size_matches_nonce_bits()
  call test_parse_chunk_len_matches_chunk_length()

  call test_pass(TEST_NAME)

contains

  function plaintext_buf() result(p)
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    allocate (p(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      p(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do
  end function

  subroutine test_single_roundtrip_blake3_kmac256()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    logical :: differ
    integer :: i

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)

    ct = enc%encrypt(pt_in)
    call assert_true(TEST_NAME, "ct length > 0", size(ct) > 0)
    if (size(ct) == size(pt_in)) then
      differ = .false.
      do i = 1, size(ct)
        if (ct(i) /= pt_in(i)) then
          differ = .true.
          exit
        end if
      end do
      call assert_true(TEST_NAME, "ct differs from pt", differ)
    end if

    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "single roundtrip", pt_out, pt_in)

    call assert_string_eq(TEST_NAME, "primitive",  enc%primitive(), "blake3")
    call assert_int_eq   (TEST_NAME, "key_bits",   int(enc%key_bits()),   1024)
    call assert_int_eq   (TEST_NAME, "mode",       int(enc%mode()),       1)
    call assert_string_eq(TEST_NAME, "mac_name",   enc%mac_name(), "kmac256")
    call assert_false    (TEST_NAME, "is_mixed",   enc%is_mixed())
    call assert_int_eq   (TEST_NAME, "seed_count", int(enc%seed_count()), 3)

    call enc%destroy()
  end subroutine

  subroutine test_triple_roundtrip_areion512_kmac256()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "areion512", 2048, "kmac256", 3)

    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "triple roundtrip", pt_out, pt_in)

    call assert_string_eq(TEST_NAME, "triple primitive",  enc%primitive(), "areion512")
    call assert_int_eq   (TEST_NAME, "triple mode",       int(enc%mode()),       3)
    call assert_int_eq   (TEST_NAME, "triple seed_count", int(enc%seed_count()), 7)

    call enc%destroy()
  end subroutine

  subroutine test_auth_roundtrip_single()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    ct = enc%encrypt_auth(pt_in)
    pt_out = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "auth roundtrip", pt_out, pt_in)
    call enc%destroy()
  end subroutine

  subroutine test_auth_decrypt_tampered_fails_with_mac_failure()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_size_kind)   :: out_len
    integer(itb_status_kind) :: rc
    integer(itb_int32_kind)  :: hsize
    integer :: i, end_b

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    ct = enc%encrypt_auth(pt_in)

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

    call enc%destroy()
  end subroutine

  subroutine test_export_import_roundtrip()
    type(itb_encryptor_t) :: enc, dec
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable, target :: blob(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(:), allocatable :: prim, mac
    integer(itb_int32_kind)   :: kb, md

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    ct = enc%encrypt_auth(pt_in)
    blob = enc%export_state()
    call assert_true(TEST_NAME, "blob non-empty", size(blob) > 0)

    call itb_encryptor_peek_config(blob, prim, kb, md, mac)
    call assert_string_eq(TEST_NAME, "peek primitive", prim, "blake3")
    call assert_int_eq   (TEST_NAME, "peek key_bits",  int(kb),   1024)
    call assert_int_eq   (TEST_NAME, "peek mode",      int(md),   1)
    call assert_string_eq(TEST_NAME, "peek mac",       mac,  "kmac256")

    call new_itb_encryptor(dec, prim, int(kb), mac, int(md))
    call dec%import_state(blob)

    pt_out = dec%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "import roundtrip", pt_out, pt_in)

    call enc%destroy()
    call dec%destroy()
  end subroutine

  subroutine test_peek_config_returns_correct_tuple()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: blob(:)
    character(:), allocatable :: prim, mac
    integer(itb_int32_kind)   :: kb, md

    call new_itb_encryptor(enc, "areion512", 2048, "hmac-blake3", 3)
    blob = enc%export_state()
    call itb_encryptor_peek_config(blob, prim, kb, md, mac)
    call assert_string_eq(TEST_NAME, "peek2 primitive", prim, "areion512")
    call assert_int_eq   (TEST_NAME, "peek2 key_bits",  int(kb),   2048)
    call assert_int_eq   (TEST_NAME, "peek2 mode",      int(md),   3)
    call assert_string_eq(TEST_NAME, "peek2 mac",       mac,  "hmac-blake3")
    call enc%destroy()
  end subroutine

  subroutine test_mixed_single_three_same_width_primitives()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)

    ! areion256 / blake3 / blake2s — all 256-bit; key_bits=1024 is a
    ! multiple of 256. The Mixed-Single constructor accepts the trio.
    call itb_encryptor_mixed_single(enc, "areion256", "blake3", "blake2s", &
                                     1024, "kmac256")
    call assert_true(TEST_NAME, "mixed.is_mixed", enc%is_mixed())

    call assert_string_eq(TEST_NAME, "mixed slot 0", enc%primitive_at(0), "areion256")
    call assert_string_eq(TEST_NAME, "mixed slot 1", enc%primitive_at(1), "blake3")
    call assert_string_eq(TEST_NAME, "mixed slot 2", enc%primitive_at(2), "blake2s")

    pt_in = plaintext_buf()
    ct = enc%encrypt_auth(pt_in)
    pt_out = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "mixed single roundtrip", pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_invalid_mode_rejected()
    ! Attempting mode=2 must surface STATUS_BAD_INPUT through the
    ! libitb FFI. The wrapper raises on the failed constructor;
    ! drop to the low-level call to observe the status code without
    ! halting.
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_prim(:), c_mac(:)
    character(*), parameter :: PRIM = "blake3"
    character(*), parameter :: MAC  = "kmac256"
    integer :: i

    allocate (c_prim(len(PRIM) + 1))
    do i = 1, len(PRIM)
      c_prim(i) = PRIM(i:i)
    end do
    c_prim(len(PRIM) + 1) = c_null_char

    allocate (c_mac(len(MAC) + 1))
    do i = 1, len(MAC)
      c_mac(i) = MAC(i:i)
    end do
    c_mac(len(MAC) + 1) = c_null_char

    handle = itb_null_handle
    rc = itb_easy_new_c(c_loc(c_prim), 1024_c_int, c_loc(c_mac), 2_c_int, handle)
    call assert_status_eq(TEST_NAME, "invalid mode rejected", rc, STATUS_BAD_INPUT)
  end subroutine

  subroutine test_close_is_idempotent()
    type(itb_encryptor_t) :: enc
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call enc%close()
    ! Idempotent close.
    call enc%close()
    call enc%destroy()
  end subroutine

  subroutine test_header_size_matches_nonce_bits()
    type(itb_encryptor_t) :: enc
    integer(itb_int32_kind) :: nb, hs

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    nb = enc%nonce_bits()
    hs = enc%header_size()
    ! header = nonce(N) + width(2) + height(2)
    call assert_int_eq(TEST_NAME, "header_size = nb/8 + 4", &
                        int(hs), int(nb) / 8 + 4)
    call enc%destroy()
  end subroutine

  subroutine test_parse_chunk_len_matches_chunk_length()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: header(:)
    integer(itb_int32_kind) :: hs
    integer(itb_size_kind)  :: parsed
    integer :: i

    pt_in = plaintext_buf()
    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    ct = enc%encrypt(pt_in)

    hs = enc%header_size()
    allocate (header(int(hs)))
    do i = 1, int(hs)
      header(i) = ct(i)
    end do
    parsed = enc%parse_chunk_len(header)
    call assert_size_eq(TEST_NAME, "parse_chunk_len matches", &
                         parsed, int(size(ct), itb_size_kind))

    call enc%destroy()
  end subroutine

end program test_easy
