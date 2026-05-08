! test_easy_mixed.f90 -- Mixed-mode Encryptor (per-slot PRF primitive
! selection) coverage on the high-level Easy surface.
!
! Mirrors the C binding's test_easy_mixed.c one-to-one. Round-trip
! on Single + Triple under itb_encryptor_mixed_single /
! itb_encryptor_mixed_triple; optional dedicated lockSeed under its
! own primitive; state-blob export / import; mixed-width rejection
! through the cgo boundary; per-slot introspection accessors
! (enc%primitive_at, enc%is_mixed).
!
! Both Mixed constructors carry `prim_l` as a Fortran `optional`
! argument. Omitting `prim_l` skips the dedicated lockSeed primitive;
! including it engages a 4th (Single) or 8th (Triple) seed slot under
! that primitive. Both paths are exercised here.
!
! The Mixed constructors raise on failure (same as the single-
! primitive `new_itb_encryptor`); the rejection sub-tests drop to
! the low-level FFI binding (`itb_easy_new_mixed_c` /
! `itb_easy_import_c`) to observe the explicit STATUS_BAD_INPUT /
! STATUS_SEED_WIDTH_MIX / non-OK rejection without halting.

program test_easy_mixed
  use, intrinsic :: iso_c_binding
  use itb_kinds
  use itb_test_helpers
  use itb_encryptor
  use itb_errors
  use itb_sys, only: itb_easy_new_mixed_c, itb_easy_import_c
  use itb_strings, only: make_c_string
  implicit none

  character(*), parameter :: TEST_NAME = "test_easy_mixed"

  call test_mixed_single_basic_roundtrip()
  call test_mixed_single_with_dedicated_lockseed()
  call test_mixed_single_aescmac_siphash_128bit()
  call test_mixed_triple_basic_roundtrip()
  call test_mixed_triple_with_dedicated_lockseed()
  call test_mixed_single_export_import()
  call test_mixed_triple_export_import_with_lockseed()
  call test_mixed_shape_mismatch()
  call test_mixed_reject_mixed_width()
  call test_mixed_reject_unknown_primitive()
  call test_default_constructor_is_not_mixed()

  call test_pass(TEST_NAME)

contains

  function token_bytes(n) result(p)
    integer, intent(in) :: n
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 41_c_int64_t + 17_c_int64_t
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_mixed_single_basic_roundtrip()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "fortran mixed Single roundtrip payload"
    integer :: i

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call itb_encryptor_mixed_single(enc, "blake3", "blake2s", "areion256", &
                                     1024, "kmac256")
    call assert_true(TEST_NAME, "mixed single is_mixed", enc%is_mixed())

    call assert_string_eq(TEST_NAME, "mixed single primitive sentinel", &
                          enc%primitive(), "mixed")

    call assert_string_eq(TEST_NAME, "slot 0", enc%primitive_at(0), "blake3")
    call assert_string_eq(TEST_NAME, "slot 1", enc%primitive_at(1), "blake2s")
    call assert_string_eq(TEST_NAME, "slot 2", enc%primitive_at(2), "areion256")

    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "mixed single roundtrip", pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_mixed_single_with_dedicated_lockseed()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "fortran mixed Single + dedicated lockSeed payload"
    integer :: i

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call itb_encryptor_mixed_single(enc, "blake3", "blake2s", "blake3", &
                                     1024, "kmac256", prim_l="areion256")
    call assert_string_eq(TEST_NAME, "lockseed slot 3", &
                          enc%primitive_at(3), "areion256")

    ct = enc%encrypt_auth(pt_in)
    pt_out = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "mixed single + lockseed roundtrip", &
                          pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_mixed_single_aescmac_siphash_128bit()
    ! SipHash-2-4 in one slot + AES-CMAC in others -- 128-bit width
    ! with mixed key shapes (siphash24 carries no fixed key bytes,
    ! aescmac carries 16). Exercises the per-slot empty / non-empty
    ! PRF-key validation in Export / Import.
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: PT_TEXT = "fortran mixed 128-bit aescmac+siphash24 mix"
    integer :: i

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call itb_encryptor_mixed_single(enc, "aescmac", "siphash24", "aescmac", &
                                     512, "hmac-sha256")
    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "mixed 128-bit roundtrip", pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_mixed_triple_basic_roundtrip()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(len=10), parameter :: WANTS(7) = &
        [character(len=10) :: "areion256", "blake3", "blake2s", "chacha20", &
                              "blake2b256", "blake3", "blake2s"]
    character(*), parameter :: PT_TEXT = "fortran mixed Triple roundtrip payload"
    integer :: i

    allocate (pt_in(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      pt_in(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call itb_encryptor_mixed_triple(enc, "areion256",                       &
                                          "blake3", "blake2s", "chacha20", &
                                          "blake2b256", "blake3", "blake2s",&
                                          1024, "kmac256")
    do i = 0, 6
      call assert_string_eq(TEST_NAME, "triple slot", &
                             enc%primitive_at(i), trim(WANTS(i + 1)))
    end do

    ct = enc%encrypt(pt_in)
    pt_out = enc%decrypt(ct)
    call assert_bytes_eq(TEST_NAME, "mixed triple roundtrip", pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_mixed_triple_with_dedicated_lockseed()
    type(itb_encryptor_t) :: enc
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: UNIT = "fortran mixed Triple + lockSeed payload"
    integer :: i, k

    ! Build a 16x-repeated plaintext to exercise multi-block paths.
    allocate (pt_in(len(UNIT) * 16))
    do k = 0, 15
      do i = 1, len(UNIT)
        pt_in(k * len(UNIT) + i) = int(iachar(UNIT(i:i)), itb_byte_kind)
      end do
    end do

    call itb_encryptor_mixed_triple(enc, "blake3",                          &
                                          "blake2s", "blake3", "blake2s", &
                                          "blake3", "blake2s", "blake3",  &
                                          1024, "kmac256",                  &
                                          prim_l="areion256")
    call assert_string_eq(TEST_NAME, "triple lockseed slot 7", &
                          enc%primitive_at(7), "areion256")

    ct = enc%encrypt_auth(pt_in)
    pt_out = enc%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "mixed triple + lockseed roundtrip", &
                          pt_out, pt_in)

    call enc%destroy()
  end subroutine

  subroutine test_mixed_single_export_import()
    type(itb_encryptor_t) :: sender, receiver
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)

    pt_in = token_bytes(2048)

    call itb_encryptor_mixed_single(sender, "blake3", "blake2s", "areion256", &
                                     1024, "kmac256")
    ct = sender%encrypt_auth(pt_in)
    blob = sender%export_state()
    call assert_true(TEST_NAME, "mixed blob non-empty", size(blob) > 0)
    call sender%destroy()

    call itb_encryptor_mixed_single(receiver, "blake3", "blake2s", "areion256", &
                                     1024, "kmac256")
    call receiver%import_state(blob)

    pt_out = receiver%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "mixed single import roundtrip", &
                          pt_out, pt_in)
    call receiver%destroy()
  end subroutine

  subroutine test_mixed_triple_export_import_with_lockseed()
    type(itb_encryptor_t) :: sender, receiver
    integer(itb_byte_kind), target, allocatable :: pt_in(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_byte_kind), allocatable :: pt_out(:)
    character(*), parameter :: UNIT = "fortran mixed Triple + lockSeed Export/Import"
    integer :: i, k

    allocate (pt_in(len(UNIT) * 16))
    do k = 0, 15
      do i = 1, len(UNIT)
        pt_in(k * len(UNIT) + i) = int(iachar(UNIT(i:i)), itb_byte_kind)
      end do
    end do

    call itb_encryptor_mixed_triple(sender, "areion256",                       &
                                              "blake3", "blake2s", "chacha20", &
                                              "blake2b256", "blake3", "blake2s",&
                                              1024, "kmac256",                  &
                                              prim_l="areion256")
    ct = sender%encrypt_auth(pt_in)
    blob = sender%export_state()
    call sender%destroy()

    call itb_encryptor_mixed_triple(receiver, "areion256",                       &
                                                "blake3", "blake2s", "chacha20", &
                                                "blake2b256", "blake3", "blake2s",&
                                                1024, "kmac256",                  &
                                                prim_l="areion256")
    call receiver%import_state(blob)

    pt_out = receiver%decrypt_auth(ct)
    call assert_bytes_eq(TEST_NAME, "mixed triple lockseed import", &
                          pt_out, pt_in)
    call receiver%destroy()
  end subroutine

  subroutine test_mixed_shape_mismatch()
    ! Mixed blob landing on a single-primitive receiver must be
    ! rejected. The wrapper raises on Import; drop to the FFI binding
    ! to observe the non-OK status without halting.
    type(itb_encryptor_t) :: mixed_sender, single_recv
    integer(itb_byte_kind), target, allocatable :: blob(:)
    integer(itb_size_kind)   :: blob_len
    integer(itb_status_kind) :: rc

    call itb_encryptor_mixed_single(mixed_sender, "blake3", "blake2s", "blake3", &
                                     1024, "kmac256")
    blob = mixed_sender%export_state()
    call mixed_sender%destroy()

    call new_itb_encryptor(single_recv, "blake3", 1024, "kmac256", 1)
    blob_len = int(size(blob), itb_size_kind)
    rc = itb_easy_import_c(single_recv%raw_handle(), c_loc(blob), blob_len)
    call assert_true(TEST_NAME, "mixed blob into single rejected", rc /= STATUS_OK)
    call single_recv%destroy()
  end subroutine

  subroutine test_mixed_reject_mixed_width()
    ! Mixing 256-bit + 512-bit primitives must surface as an error.
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_n(:), c_d(:), c_s(:), c_mac(:)

    call make_c_string("blake3",    c_n)   ! 256-bit
    call make_c_string("areion512", c_d)   ! 512-bit -- mismatch
    call make_c_string("blake3",    c_s)
    call make_c_string("kmac256",   c_mac)

    handle = itb_null_handle
    rc = itb_easy_new_mixed_c(c_loc(c_n), c_loc(c_d), c_loc(c_s), &
                                c_null_ptr,                        &
                                1024_c_int, c_loc(c_mac), handle)
    call assert_true(TEST_NAME, "mixed-width rejected", rc /= STATUS_OK)
    call assert_true(TEST_NAME, "handle stays null on reject", &
                      handle == itb_null_handle)
  end subroutine

  subroutine test_mixed_reject_unknown_primitive()
    integer(itb_handle_kind) :: handle
    integer(itb_status_kind) :: rc
    character(kind=c_char), allocatable, target :: c_n(:), c_d(:), c_s(:), c_mac(:)

    call make_c_string("no-such-primitive", c_n)
    call make_c_string("blake3",            c_d)
    call make_c_string("blake3",            c_s)
    call make_c_string("kmac256",           c_mac)

    handle = itb_null_handle
    rc = itb_easy_new_mixed_c(c_loc(c_n), c_loc(c_d), c_loc(c_s), &
                                c_null_ptr,                        &
                                1024_c_int, c_loc(c_mac), handle)
    call assert_true(TEST_NAME, "unknown primitive rejected", rc /= STATUS_OK)
  end subroutine

  subroutine test_default_constructor_is_not_mixed()
    ! Single-primitive default constructor must not report is_mixed,
    ! and primitive_at must echo the same primitive on every slot.
    type(itb_encryptor_t) :: enc
    integer :: i

    call new_itb_encryptor(enc, "blake3", 1024, "kmac256", 1)
    call assert_false(TEST_NAME, "default not mixed", enc%is_mixed())

    do i = 0, 2
      call assert_string_eq(TEST_NAME, "default slot", &
                             enc%primitive_at(i), "blake3")
    end do
    call enc%destroy()
  end subroutine

end program test_easy_mixed
