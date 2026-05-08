! test_blob.f90 -- Blob128 / Blob256 / Blob512 export / import coverage.
!
! Confirms the native Blob containers round-trip Single + Triple
! Ouroboros material (with and without dedicated lockSeed, with and
! without MAC) and preserve the captured globals across export /
! import.
!
! Slot indexing follows the libitb convention: 0 = noise, 1 = data,
! 2 = start (Single mode), 3 = optional dedicated lockSeed (any mode),
! 4..6 = data1 / data2 / data3, 7..9 = start1 / start2 / start3
! (Triple mode). The constants below match those defined in the C
! binding's itb.h.
!
! The high-level wrappers raise on any non-OK status. The malformed /
! version-too-new / mode-mismatch sub-tests therefore drop to the
! low-level FFI binding (`itb_blob_import_c` / `itb_blob_import3_c`
! from `itb_sys`) so the explicit failure status can be observed
! without terminating the test program.

program test_blob
  use itb_kinds
  use itb_seed
  use itb_mac
  use itb_cipher
  use itb_library
  use itb_blob
  use itb_errors
  use itb_sys, only: itb_blob_import_c, itb_blob_import3_c
  use itb_test_helpers
  implicit none

  ! Slot integer constants (mirrors C binding's ITB_BLOB_SLOT_*).
  integer, parameter :: SLOT_N  = 0
  integer, parameter :: SLOT_D  = 1
  integer, parameter :: SLOT_S  = 2
  integer, parameter :: SLOT_L  = 3
  integer, parameter :: SLOT_D1 = 4
  integer, parameter :: SLOT_D2 = 5
  integer, parameter :: SLOT_D3 = 6
  integer, parameter :: SLOT_S1 = 7
  integer, parameter :: SLOT_S2 = 8
  integer, parameter :: SLOT_S3 = 9

  character(*), parameter :: TEST_NAME = "test_blob"

  integer(itb_int32_kind) :: orig_nb, orig_bf, orig_bs, orig_ls

  call capture_globals(orig_nb, orig_bf, orig_bs, orig_ls)

  call test_blob256_single_export_import_roundtrip()
  call test_blob256_freshly_constructed_has_unset_mode()
  call test_construct_each_width()
  call test_blob512_single_full_matrix()
  call test_blob512_triple_full_matrix()
  call test_blob256_single()
  call test_blob256_triple()
  call test_blob128_siphash_single()
  call test_blob128_aescmac_single()
  call test_blob_mode_mismatch()
  call test_blob_malformed()

  call restore_globals(int(orig_nb), int(orig_bf), int(orig_bs), int(orig_ls))
  call test_pass(TEST_NAME)

contains

  subroutine capture_globals(nb, bf, bs, ls)
    integer(itb_int32_kind), intent(out) :: nb, bf, bs, ls
    nb = itb_get_nonce_bits()
    bf = itb_get_barrier_fill()
    bs = itb_get_bit_soup()
    ls = itb_get_lock_soup()
  end subroutine

  subroutine restore_globals(nb, bf, bs, ls)
    integer, intent(in) :: nb, bf, bs, ls
    call itb_set_nonce_bits(nb)
    call itb_set_barrier_fill(bf)
    call itb_set_bit_soup(bs)
    call itb_set_lock_soup(ls)
  end subroutine

  subroutine engage_full_globals()
    call itb_set_nonce_bits(512)
    call itb_set_barrier_fill(4)
    call itb_set_bit_soup(1)
    call itb_set_lock_soup(1)
  end subroutine

  subroutine reset_globals()
    call itb_set_nonce_bits(128)
    call itb_set_barrier_fill(1)
    call itb_set_bit_soup(0)
    call itb_set_lock_soup(0)
  end subroutine

  subroutine assert_globals_restored(label, nb, bf, bs, ls)
    character(*), intent(in) :: label
    integer,      intent(in) :: nb, bf, bs, ls
    call assert_int_eq(TEST_NAME, label // " nonce_bits",   int(itb_get_nonce_bits()),   nb)
    call assert_int_eq(TEST_NAME, label // " barrier_fill", int(itb_get_barrier_fill()), bf)
    call assert_int_eq(TEST_NAME, label // " bit_soup",     int(itb_get_bit_soup()),     bs)
    call assert_int_eq(TEST_NAME, label // " lock_soup",    int(itb_get_lock_soup()),    ls)
  end subroutine

  function pseudo_payload(n, salt) result(p)
    integer, intent(in) :: n, salt
    integer(itb_byte_kind), allocatable :: p(:)
    integer :: i
    integer(c_int64_t) :: v
    allocate (p(n))
    do i = 1, n
      v = int(i - 1, c_int64_t) * 13_c_int64_t + 11_c_int64_t + int(salt, c_int64_t)
      p(i) = int(iand(v, 255_c_int64_t), itb_byte_kind)
    end do
  end function

  subroutine test_blob256_single_export_import_roundtrip()
    type(itb_blob256_t) :: sender, receiver
    integer(itb_byte_kind), target :: key_n(32), key_d(32), key_s(32), mac_key(32)
    integer(itb_u64_kind),  target :: comps_n(16), comps_d(16), comps_s(16)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_byte_kind), allocatable :: got_key(:)
    integer(itb_u64_kind),  allocatable :: got_comps(:)
    integer(itb_byte_kind), allocatable :: got_mac_key(:)
    character(:), allocatable :: got_mac_name
    integer(itb_int32_kind) :: width, mode
    integer :: i

    do i = 1, 32
      key_n(i)   = ieor(int(z'A0', itb_byte_kind), int(i - 1, itb_byte_kind))
      key_d(i)   = ieor(int(z'B0', itb_byte_kind), int(i - 1, itb_byte_kind))
      key_s(i)   = ieor(int(z'C0', itb_byte_kind), int(i - 1, itb_byte_kind))
      mac_key(i) = ieor(int(z'D0', itb_byte_kind), int(i - 1, itb_byte_kind))
    end do
    do i = 1, 16
      comps_n(i) = int(z'1000', itb_u64_kind) + int(i - 1, itb_u64_kind)
      comps_d(i) = int(z'2000', itb_u64_kind) + int(i - 1, itb_u64_kind)
      comps_s(i) = int(z'3000', itb_u64_kind) + int(i - 1, itb_u64_kind)
    end do

    call new_itb_blob256(sender)
    call sender%set_key(SLOT_N, key_n);   call sender%set_components(SLOT_N, comps_n)
    call sender%set_key(SLOT_D, key_d);   call sender%set_components(SLOT_D, comps_d)
    call sender%set_key(SLOT_S, key_s);   call sender%set_components(SLOT_S, comps_s)
    call sender%set_mac_key(mac_key)
    call sender%set_mac_name("kmac256")

    blob_bytes = sender%export(opts=ITB_BLOB_OPT_MAC)
    call assert_true(TEST_NAME, "blob_bytes non-empty", size(blob_bytes) > 0)

    call new_itb_blob256(receiver)
    call receiver%import(blob_bytes)

    width = receiver%width()
    mode  = receiver%mode()
    call assert_int_eq(TEST_NAME, "receiver width", int(width), 256)
    call assert_int_eq(TEST_NAME, "receiver mode",  int(mode),  1)

    got_key = receiver%get_key(SLOT_N)
    call assert_int_eq(TEST_NAME, "key_n length", size(got_key), 32)
    call assert_bytes_eq(TEST_NAME, "key_n bytes", got_key, key_n)
    got_key = receiver%get_key(SLOT_D)
    call assert_bytes_eq(TEST_NAME, "key_d bytes", got_key, key_d)
    got_key = receiver%get_key(SLOT_S)
    call assert_bytes_eq(TEST_NAME, "key_s bytes", got_key, key_s)

    got_comps = receiver%get_components(SLOT_N)
    call assert_u64_array_eq(TEST_NAME, "comps_n", got_comps, comps_n)
    got_comps = receiver%get_components(SLOT_D)
    call assert_u64_array_eq(TEST_NAME, "comps_d", got_comps, comps_d)
    got_comps = receiver%get_components(SLOT_S)
    call assert_u64_array_eq(TEST_NAME, "comps_s", got_comps, comps_s)

    got_mac_key = receiver%get_mac_key()
    call assert_int_eq(TEST_NAME, "mac_key length", size(got_mac_key), 32)
    call assert_bytes_eq(TEST_NAME, "mac_key bytes", got_mac_key, mac_key)

    got_mac_name = receiver%get_mac_name()
    call assert_string_eq(TEST_NAME, "mac_name", got_mac_name, "kmac256")

    call sender%destroy(); call receiver%destroy()
  end subroutine

  subroutine test_blob256_freshly_constructed_has_unset_mode()
    type(itb_blob256_t) :: b
    call new_itb_blob256(b)
    call assert_int_eq(TEST_NAME, "fresh blob256 width", int(b%width()), 256)
    call assert_int_eq(TEST_NAME, "fresh blob256 mode",  int(b%mode()),  0)
    call b%destroy()
  end subroutine

  subroutine test_construct_each_width()
    type(itb_blob128_t) :: b1
    type(itb_blob256_t) :: b2
    type(itb_blob512_t) :: b3
    integer :: i

    call new_itb_blob128(b1)
    call assert_int_eq(TEST_NAME, "blob128 width", int(b1%width()), 128)
    call assert_int_eq(TEST_NAME, "blob128 mode",  int(b1%mode()),  0)
    call b1%destroy()

    call new_itb_blob256(b2)
    call assert_int_eq(TEST_NAME, "blob256 width", int(b2%width()), 256)
    call assert_int_eq(TEST_NAME, "blob256 mode",  int(b2%mode()),  0)
    call b2%destroy()

    call new_itb_blob512(b3)
    call assert_int_eq(TEST_NAME, "blob512 width", int(b3%width()), 512)
    call assert_int_eq(TEST_NAME, "blob512 mode",  int(b3%mode()),  0)
    call b3%destroy()

    ! Construct + destroy cycle to exercise the lifecycle path.
    do i = 1, 16
      call new_itb_blob256(b2)
      call b2%destroy()
    end do
  end subroutine

  subroutine blob512_single_one(plaintext, with_ls, with_mac)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    logical, intent(in) :: with_ls, with_mac
    character(*), parameter :: PRIMITIVE = "areion512"
    integer, parameter :: KEY_BITS = 2048
    type(itb_seed_t) :: ns, ds, ss, ls
    type(itb_seed_t) :: ns2, ds2, ss2, ls2
    type(itb_mac_t)  :: mac, mac2
    type(itb_blob512_t) :: src, dst
    integer(itb_byte_kind), target :: mac_key(32)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:), got_mk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    character(:), allocatable :: got_mn
    integer :: opts, i

    do i = 1, 32
      mac_key(i) = ieor(int(z'55', itb_byte_kind), int(i - 1, itb_byte_kind))
    end do

    call new_itb_seed(ns, PRIMITIVE, KEY_BITS)
    call new_itb_seed(ds, PRIMITIVE, KEY_BITS)
    call new_itb_seed(ss, PRIMITIVE, KEY_BITS)
    if (with_ls) then
      call new_itb_seed(ls, PRIMITIVE, KEY_BITS)
      call ns%attach_lock_seed(ls)
    end if
    if (with_mac) then
      call new_itb_mac(mac, "kmac256", mac_key)
    end if

    if (with_mac) then
      ct = itb_encrypt_auth(ns, ds, ss, mac, plaintext)
    else
      ct = itb_encrypt(ns, ds, ss, plaintext)
    end if

    call new_itb_blob512(src)
    hk = ns%hash_key();      comps = ns%components()
    call src%set_key(SLOT_N, hk); call src%set_components(SLOT_N, comps)
    hk = ds%hash_key();      comps = ds%components()
    call src%set_key(SLOT_D, hk); call src%set_components(SLOT_D, comps)
    hk = ss%hash_key();      comps = ss%components()
    call src%set_key(SLOT_S, hk); call src%set_components(SLOT_S, comps)
    if (with_ls) then
      hk = ls%hash_key();    comps = ls%components()
      call src%set_key(SLOT_L, hk); call src%set_components(SLOT_L, comps)
    end if
    if (with_mac) then
      call src%set_mac_key(mac_key)
      call src%set_mac_name("kmac256")
    end if

    opts = 0
    if (with_ls)  opts = ior(opts, ITB_BLOB_OPT_LOCKSEED)
    if (with_mac) opts = ior(opts, ITB_BLOB_OPT_MAC)
    blob_bytes = src%export(opts=opts)

    call reset_globals()
    call new_itb_blob512(dst)
    call dst%import(blob_bytes)
    call assert_int_eq(TEST_NAME, "single blob512 dst mode", int(dst%mode()), 1)
    call assert_globals_restored("single blob512 globals", 512, 4, 1, 1)

    ! Rebuild seeds from the imported blob.
    comps = dst%get_components(SLOT_N); hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(ns2, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_D); hk = dst%get_key(SLOT_D)
    call itb_seed_from_components(ds2, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_S); hk = dst%get_key(SLOT_S)
    call itb_seed_from_components(ss2, PRIMITIVE, comps, hk)
    if (with_ls) then
      comps = dst%get_components(SLOT_L); hk = dst%get_key(SLOT_L)
      call itb_seed_from_components(ls2, PRIMITIVE, comps, hk)
      call ns2%attach_lock_seed(ls2)
    end if
    if (with_mac) then
      got_mn = dst%get_mac_name()
      call assert_string_eq(TEST_NAME, "single blob512 mac_name", got_mn, "kmac256")
      got_mk = dst%get_mac_key()
      call assert_int_eq(TEST_NAME, "single blob512 mac_key len", size(got_mk), 32)
      call assert_bytes_eq(TEST_NAME, "single blob512 mac_key", got_mk, mac_key)
      call new_itb_mac(mac2, "kmac256", got_mk)
    end if

    if (with_mac) then
      pt = itb_decrypt_auth(ns2, ds2, ss2, mac2, ct)
    else
      pt = itb_decrypt(ns2, ds2, ss2, ct)
    end if
    call assert_bytes_eq(TEST_NAME, "single blob512 roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
    if (with_ls) then
      call ls%destroy(); call ls2%destroy()
    end if
    if (with_mac) then
      call mac%destroy(); call mac2%destroy()
    end if
  end subroutine

  subroutine test_blob512_single_full_matrix()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    integer :: with_ls, with_mac

    plaintext = pseudo_payload(64, 1)
    do with_ls = 0, 1
      do with_mac = 0, 1
        call capture_globals(nb, bf, bs, ls_v)
        call engage_full_globals()
        call blob512_single_one(plaintext, with_ls == 1, with_mac == 1)
        call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
      end do
    end do
  end subroutine

  subroutine blob512_triple_one(plaintext, with_ls, with_mac)
    integer(itb_byte_kind), target, intent(in) :: plaintext(:)
    logical, intent(in) :: with_ls, with_mac
    character(*), parameter :: PRIMITIVE = "areion512"
    integer, parameter :: KEY_BITS = 2048
    type(itb_seed_t) :: s1, s2, s3, s4, s5, s6, s7, ls
    type(itb_seed_t) :: t1, t2, t3, t4, t5, t6, t7, ls2
    type(itb_mac_t)  :: mac, mac2
    type(itb_blob512_t) :: src, dst
    integer(itb_byte_kind), target :: mac_key(32)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:), got_mk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer :: opts, i

    do i = 1, 32
      mac_key(i) = ieor(int(z'37', itb_byte_kind), int(i - 1, itb_byte_kind))
    end do

    call new_itb_seed(s1, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s2, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s3, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s4, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s5, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s6, PRIMITIVE, KEY_BITS)
    call new_itb_seed(s7, PRIMITIVE, KEY_BITS)
    if (with_ls) then
      call new_itb_seed(ls, PRIMITIVE, KEY_BITS)
      call s1%attach_lock_seed(ls)
    end if
    if (with_mac) then
      call new_itb_mac(mac, "kmac256", mac_key)
    end if

    if (with_mac) then
      ct = itb_encrypt_auth_triple(s1, s2, s3, s4, s5, s6, s7, mac, plaintext)
    else
      ct = itb_encrypt_triple(s1, s2, s3, s4, s5, s6, s7, plaintext)
    end if

    call new_itb_blob512(src)
    hk = s1%hash_key(); comps = s1%components()
    call src%set_key(SLOT_N,  hk); call src%set_components(SLOT_N,  comps)
    hk = s2%hash_key(); comps = s2%components()
    call src%set_key(SLOT_D1, hk); call src%set_components(SLOT_D1, comps)
    hk = s3%hash_key(); comps = s3%components()
    call src%set_key(SLOT_D2, hk); call src%set_components(SLOT_D2, comps)
    hk = s4%hash_key(); comps = s4%components()
    call src%set_key(SLOT_D3, hk); call src%set_components(SLOT_D3, comps)
    hk = s5%hash_key(); comps = s5%components()
    call src%set_key(SLOT_S1, hk); call src%set_components(SLOT_S1, comps)
    hk = s6%hash_key(); comps = s6%components()
    call src%set_key(SLOT_S2, hk); call src%set_components(SLOT_S2, comps)
    hk = s7%hash_key(); comps = s7%components()
    call src%set_key(SLOT_S3, hk); call src%set_components(SLOT_S3, comps)
    if (with_ls) then
      hk = ls%hash_key(); comps = ls%components()
      call src%set_key(SLOT_L, hk); call src%set_components(SLOT_L, comps)
    end if
    if (with_mac) then
      call src%set_mac_key(mac_key)
      call src%set_mac_name("kmac256")
    end if

    opts = 0
    if (with_ls)  opts = ior(opts, ITB_BLOB_OPT_LOCKSEED)
    if (with_mac) opts = ior(opts, ITB_BLOB_OPT_MAC)
    blob_bytes = src%export_3(opts=opts)

    call reset_globals()
    call new_itb_blob512(dst)
    call dst%import_3(blob_bytes)
    call assert_int_eq(TEST_NAME, "triple blob512 dst mode", int(dst%mode()), 3)
    call assert_globals_restored("triple blob512 globals", 512, 4, 1, 1)

    comps = dst%get_components(SLOT_N);  hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(t1, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_D1); hk = dst%get_key(SLOT_D1)
    call itb_seed_from_components(t2, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_D2); hk = dst%get_key(SLOT_D2)
    call itb_seed_from_components(t3, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_D3); hk = dst%get_key(SLOT_D3)
    call itb_seed_from_components(t4, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_S1); hk = dst%get_key(SLOT_S1)
    call itb_seed_from_components(t5, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_S2); hk = dst%get_key(SLOT_S2)
    call itb_seed_from_components(t6, PRIMITIVE, comps, hk)
    comps = dst%get_components(SLOT_S3); hk = dst%get_key(SLOT_S3)
    call itb_seed_from_components(t7, PRIMITIVE, comps, hk)
    if (with_ls) then
      comps = dst%get_components(SLOT_L); hk = dst%get_key(SLOT_L)
      call itb_seed_from_components(ls2, PRIMITIVE, comps, hk)
      call t1%attach_lock_seed(ls2)
    end if
    if (with_mac) then
      got_mk = dst%get_mac_key()
      call new_itb_mac(mac2, "kmac256", got_mk)
    end if

    if (with_mac) then
      pt = itb_decrypt_auth_triple(t1, t2, t3, t4, t5, t6, t7, mac2, ct)
    else
      pt = itb_decrypt_triple(t1, t2, t3, t4, t5, t6, t7, ct)
    end if
    call assert_bytes_eq(TEST_NAME, "triple blob512 roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call s1%destroy(); call s2%destroy(); call s3%destroy(); call s4%destroy()
    call s5%destroy(); call s6%destroy(); call s7%destroy()
    call t1%destroy(); call t2%destroy(); call t3%destroy(); call t4%destroy()
    call t5%destroy(); call t6%destroy(); call t7%destroy()
    if (with_ls) then
      call ls%destroy(); call ls2%destroy()
    end if
    if (with_mac) then
      call mac%destroy(); call mac2%destroy()
    end if
  end subroutine

  subroutine test_blob512_triple_full_matrix()
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    integer :: with_ls, with_mac

    plaintext = pseudo_payload(64, 2)
    do with_ls = 0, 1
      do with_mac = 0, 1
        call capture_globals(nb, bf, bs, ls_v)
        call engage_full_globals()
        call blob512_triple_one(plaintext, with_ls == 1, with_mac == 1)
        call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
      end do
    end do
  end subroutine

  subroutine test_blob256_single()
    type(itb_seed_t) :: ns, ds, ss, ns2, ds2, ss2
    type(itb_blob256_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    character(*), parameter :: PT_TEXT = "fortran blob256 single round-trip"
    integer :: i

    call capture_globals(nb, bf, bs, ls_v)
    call engage_full_globals()

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    ct = itb_encrypt(ns, ds, ss, plaintext)

    call new_itb_blob256(src)
    hk = ns%hash_key(); comps = ns%components()
    call src%set_key(SLOT_N, hk); call src%set_components(SLOT_N, comps)
    hk = ds%hash_key(); comps = ds%components()
    call src%set_key(SLOT_D, hk); call src%set_components(SLOT_D, comps)
    hk = ss%hash_key(); comps = ss%components()
    call src%set_key(SLOT_S, hk); call src%set_components(SLOT_S, comps)
    blob_bytes = src%export()

    call reset_globals()
    call new_itb_blob256(dst)
    call dst%import(blob_bytes)
    call assert_int_eq(TEST_NAME, "blob256 single dst mode", int(dst%mode()), 1)

    comps = dst%get_components(SLOT_N); hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(ns2, "blake3", comps, hk)
    comps = dst%get_components(SLOT_D); hk = dst%get_key(SLOT_D)
    call itb_seed_from_components(ds2, "blake3", comps, hk)
    comps = dst%get_components(SLOT_S); hk = dst%get_key(SLOT_S)
    call itb_seed_from_components(ss2, "blake3", comps, hk)
    pt = itb_decrypt(ns2, ds2, ss2, ct)
    call assert_bytes_eq(TEST_NAME, "blob256 single roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
    call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
  end subroutine

  subroutine test_blob256_triple()
    type(itb_seed_t) :: s1, s2, s3, s4, s5, s6, s7
    type(itb_seed_t) :: t1, t2, t3, t4, t5, t6, t7
    type(itb_blob256_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    character(*), parameter :: PT_TEXT = "fortran blob256 triple round-trip"
    integer :: i

    call capture_globals(nb, bf, bs, ls_v)
    call engage_full_globals()

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(s1, "blake3", 1024)
    call new_itb_seed(s2, "blake3", 1024)
    call new_itb_seed(s3, "blake3", 1024)
    call new_itb_seed(s4, "blake3", 1024)
    call new_itb_seed(s5, "blake3", 1024)
    call new_itb_seed(s6, "blake3", 1024)
    call new_itb_seed(s7, "blake3", 1024)
    ct = itb_encrypt_triple(s1, s2, s3, s4, s5, s6, s7, plaintext)

    call new_itb_blob256(src)
    hk = s1%hash_key(); comps = s1%components()
    call src%set_key(SLOT_N,  hk); call src%set_components(SLOT_N,  comps)
    hk = s2%hash_key(); comps = s2%components()
    call src%set_key(SLOT_D1, hk); call src%set_components(SLOT_D1, comps)
    hk = s3%hash_key(); comps = s3%components()
    call src%set_key(SLOT_D2, hk); call src%set_components(SLOT_D2, comps)
    hk = s4%hash_key(); comps = s4%components()
    call src%set_key(SLOT_D3, hk); call src%set_components(SLOT_D3, comps)
    hk = s5%hash_key(); comps = s5%components()
    call src%set_key(SLOT_S1, hk); call src%set_components(SLOT_S1, comps)
    hk = s6%hash_key(); comps = s6%components()
    call src%set_key(SLOT_S2, hk); call src%set_components(SLOT_S2, comps)
    hk = s7%hash_key(); comps = s7%components()
    call src%set_key(SLOT_S3, hk); call src%set_components(SLOT_S3, comps)
    blob_bytes = src%export_3()

    call reset_globals()
    call new_itb_blob256(dst)
    call dst%import_3(blob_bytes)
    call assert_int_eq(TEST_NAME, "blob256 triple dst mode", int(dst%mode()), 3)

    comps = dst%get_components(SLOT_N);  hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(t1, "blake3", comps, hk)
    comps = dst%get_components(SLOT_D1); hk = dst%get_key(SLOT_D1)
    call itb_seed_from_components(t2, "blake3", comps, hk)
    comps = dst%get_components(SLOT_D2); hk = dst%get_key(SLOT_D2)
    call itb_seed_from_components(t3, "blake3", comps, hk)
    comps = dst%get_components(SLOT_D3); hk = dst%get_key(SLOT_D3)
    call itb_seed_from_components(t4, "blake3", comps, hk)
    comps = dst%get_components(SLOT_S1); hk = dst%get_key(SLOT_S1)
    call itb_seed_from_components(t5, "blake3", comps, hk)
    comps = dst%get_components(SLOT_S2); hk = dst%get_key(SLOT_S2)
    call itb_seed_from_components(t6, "blake3", comps, hk)
    comps = dst%get_components(SLOT_S3); hk = dst%get_key(SLOT_S3)
    call itb_seed_from_components(t7, "blake3", comps, hk)
    pt = itb_decrypt_triple(t1, t2, t3, t4, t5, t6, t7, ct)
    call assert_bytes_eq(TEST_NAME, "blob256 triple roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call s1%destroy(); call s2%destroy(); call s3%destroy(); call s4%destroy()
    call s5%destroy(); call s6%destroy(); call s7%destroy()
    call t1%destroy(); call t2%destroy(); call t3%destroy(); call t4%destroy()
    call t5%destroy(); call t6%destroy(); call t7%destroy()
    call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
  end subroutine

  subroutine test_blob128_siphash_single()
    type(itb_seed_t) :: ns, ds, ss, ns2, ds2, ss2
    type(itb_blob128_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    character(*), parameter :: PT_TEXT = "fortran blob128 siphash round-trip"
    integer :: i

    call capture_globals(nb, bf, bs, ls_v)
    call engage_full_globals()

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "siphash24", 512)
    call new_itb_seed(ds, "siphash24", 512)
    call new_itb_seed(ss, "siphash24", 512)
    ct = itb_encrypt(ns, ds, ss, plaintext)

    call new_itb_blob128(src)
    hk = ns%hash_key()
    call assert_int_eq(TEST_NAME, "siphash hash_key length", size(hk), 0)
    comps = ns%components()
    call src%set_key(SLOT_N, hk); call src%set_components(SLOT_N, comps)
    hk = ds%hash_key(); comps = ds%components()
    call src%set_key(SLOT_D, hk); call src%set_components(SLOT_D, comps)
    hk = ss%hash_key(); comps = ss%components()
    call src%set_key(SLOT_S, hk); call src%set_components(SLOT_S, comps)
    blob_bytes = src%export()

    call reset_globals()
    call new_itb_blob128(dst)
    call dst%import(blob_bytes)

    comps = dst%get_components(SLOT_N); hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(ns2, "siphash24", comps, hk)
    comps = dst%get_components(SLOT_D); hk = dst%get_key(SLOT_D)
    call itb_seed_from_components(ds2, "siphash24", comps, hk)
    comps = dst%get_components(SLOT_S); hk = dst%get_key(SLOT_S)
    call itb_seed_from_components(ss2, "siphash24", comps, hk)
    pt = itb_decrypt(ns2, ds2, ss2, ct)
    call assert_bytes_eq(TEST_NAME, "blob128 siphash roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
    call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
  end subroutine

  subroutine test_blob128_aescmac_single()
    type(itb_seed_t) :: ns, ds, ss, ns2, ds2, ss2
    type(itb_blob128_t) :: src, dst
    integer(itb_byte_kind), target, allocatable :: plaintext(:)
    integer(itb_byte_kind), target, allocatable :: ct(:)
    integer(itb_byte_kind), allocatable :: pt(:)
    integer(itb_byte_kind), allocatable :: hk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_int32_kind) :: nb, bf, bs, ls_v
    character(*), parameter :: PT_TEXT = "fortran blob128 aescmac round-trip"
    integer :: i

    call capture_globals(nb, bf, bs, ls_v)
    call engage_full_globals()

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "aescmac", 512)
    call new_itb_seed(ds, "aescmac", 512)
    call new_itb_seed(ss, "aescmac", 512)
    ct = itb_encrypt(ns, ds, ss, plaintext)

    call new_itb_blob128(src)
    hk = ns%hash_key()
    call assert_int_eq(TEST_NAME, "aescmac hash_key length", size(hk), 16)
    comps = ns%components()
    call src%set_key(SLOT_N, hk); call src%set_components(SLOT_N, comps)
    hk = ds%hash_key(); comps = ds%components()
    call src%set_key(SLOT_D, hk); call src%set_components(SLOT_D, comps)
    hk = ss%hash_key(); comps = ss%components()
    call src%set_key(SLOT_S, hk); call src%set_components(SLOT_S, comps)
    blob_bytes = src%export()

    call reset_globals()
    call new_itb_blob128(dst)
    call dst%import(blob_bytes)

    comps = dst%get_components(SLOT_N); hk = dst%get_key(SLOT_N)
    call itb_seed_from_components(ns2, "aescmac", comps, hk)
    comps = dst%get_components(SLOT_D); hk = dst%get_key(SLOT_D)
    call itb_seed_from_components(ds2, "aescmac", comps, hk)
    comps = dst%get_components(SLOT_S); hk = dst%get_key(SLOT_S)
    call itb_seed_from_components(ss2, "aescmac", comps, hk)
    pt = itb_decrypt(ns2, ds2, ss2, ct)
    call assert_bytes_eq(TEST_NAME, "blob128 aescmac roundtrip", pt, plaintext)

    call src%destroy(); call dst%destroy()
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call ns2%destroy(); call ds2%destroy(); call ss2%destroy()
    call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
  end subroutine

  subroutine test_blob_mode_mismatch()
    type(itb_seed_t) :: ns, ds, ss
    type(itb_blob512_t) :: src, dst
    integer(itb_byte_kind), allocatable :: hk(:)
    integer(itb_u64_kind),  allocatable :: comps(:)
    integer(itb_byte_kind), target, allocatable :: blob_bytes(:)
    integer(itb_size_kind) :: blob_len
    integer(itb_status_kind) :: rc
    integer(itb_int32_kind) :: nb, bf, bs, ls_v

    call capture_globals(nb, bf, bs, ls_v)
    call engage_full_globals()

    call new_itb_seed(ns, "areion512", 1024)
    call new_itb_seed(ds, "areion512", 1024)
    call new_itb_seed(ss, "areion512", 1024)

    call new_itb_blob512(src)
    hk = ns%hash_key(); comps = ns%components()
    call src%set_key(SLOT_N, hk); call src%set_components(SLOT_N, comps)
    hk = ds%hash_key(); comps = ds%components()
    call src%set_key(SLOT_D, hk); call src%set_components(SLOT_D, comps)
    hk = ss%hash_key(); comps = ss%components()
    call src%set_key(SLOT_S, hk); call src%set_components(SLOT_S, comps)
    blob_bytes = src%export()

    call new_itb_blob512(dst)
    ! Single-mode blob fed to import3 must surface STATUS_BLOB_MODE_MISMATCH.
    blob_len = int(size(blob_bytes), itb_size_kind)
    rc = itb_blob_import3_c(dst%raw_handle(), c_loc(blob_bytes), blob_len)
    call assert_status_eq(TEST_NAME, "single-into-import3 rejected", &
                           rc, STATUS_BLOB_MODE_MISMATCH)

    call src%destroy(); call dst%destroy()
    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call restore_globals(int(nb), int(bf), int(bs), int(ls_v))
  end subroutine

  subroutine test_blob_malformed()
    type(itb_blob512_t) :: b
    integer(itb_byte_kind), target, allocatable :: garbage(:)
    integer(itb_size_kind) :: glen
    integer(itb_status_kind) :: rc
    character(*), parameter :: G = "{not json"
    integer :: i

    call new_itb_blob512(b)
    allocate (garbage(len(G)))
    do i = 1, len(G)
      garbage(i) = int(iachar(G(i:i)), itb_byte_kind)
    end do
    glen = int(size(garbage), itb_size_kind)
    rc = itb_blob_import_c(b%raw_handle(), c_loc(garbage), glen)
    call assert_status_eq(TEST_NAME, "malformed blob rejected", &
                           rc, STATUS_BLOB_MALFORMED)
    call b%destroy()
  end subroutine

end program test_blob
