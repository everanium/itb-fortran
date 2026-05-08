! test_attach_lock_seed.f90 -- coverage for the low-level
! itb_seed_attach_lock_seed mutator.
!
! The dedicated lockSeed routes the bit-permutation derivation through
! its own state instead of the noiseSeed: the per-chunk PRF closure
! captures BOTH the lockSeed's components AND its hash function, so
! the lockSeed primitive may legitimately differ from the noiseSeed
! primitive within the same native hash width -- keying-material
! isolation plus algorithm diversity for defence-in-depth on the
! bit-permutation channel, without changing the public encrypt /
! decrypt signatures.
!
! The bit-permutation overlay must be engaged via itb_set_bit_soup or
! itb_set_lock_soup before any encrypt call -- without the overlay,
! the dedicated lockSeed has no observable effect on the wire output,
! and the Go-side build-PRF guard surfaces as STATUS_ENCRYPT_FAILED.
! These tests exercise both the round-trip path with overlay engaged
! and the attach-time misuse rejections (self-attach, post-encrypt
! switching, width mismatch).
!
! The high-level wrappers raise on any non-OK status, so the tests
! that intend to OBSERVE a non-OK status (self-attach, width-mismatch,
! post-encrypt re-attach, overlay-off encrypt failure) drop to the
! low-level FFI binding (`itb_attach_lock_seed_c` / `itb_encrypt_c`
! from `itb_sys`) so the explicit failure status can be inspected
! without terminating the test program.

program test_attach_lock_seed
  use itb_kinds
  use itb_seed
  use itb_cipher
  use itb_library
  use itb_errors
  use itb_sys, only: itb_attach_lock_seed_c, itb_encrypt_c
  use itb_test_helpers
  implicit none

  character(*), parameter :: TEST_NAME = "test_attach_lock_seed"

  integer(itb_int32_kind) :: orig_bs, orig_ls

  orig_bs = itb_get_bit_soup()
  orig_ls = itb_get_lock_soup()

  call test_roundtrip()
  call test_persistence()
  call test_self_attach_rejected()
  call test_width_mismatch_rejected()
  call test_post_encrypt_attach_rejected()
  call test_overlay_off_fails_on_encrypt()

  call itb_set_bit_soup(int(orig_bs))
  call itb_set_lock_soup(int(orig_ls))

  call test_pass(TEST_NAME)

contains

  subroutine engage_overlay()
    ! set_lock_soup(1) auto-couples bit_soup=1 inside libitb.
    call itb_set_lock_soup(1)
  end subroutine

  subroutine disengage_overlay()
    call itb_set_bit_soup(0)
    call itb_set_lock_soup(0)
  end subroutine

  subroutine test_roundtrip()
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    type(itb_seed_t) :: ns, ds, ss, ls
    character(*), parameter :: PT_TEXT = "attach_lock_seed roundtrip payload"
    integer :: i

    call engage_overlay()
    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_seed(ls, "blake3", 1024)
    call ns%attach_lock_seed(ls)

    ct = itb_encrypt(ns, ds, ss, plaintext)
    pt = itb_decrypt(ns, ds, ss, ct)
    call assert_bytes_eq(TEST_NAME, "roundtrip recovers plaintext", pt, plaintext)

    call ns%destroy(); call ds%destroy(); call ss%destroy(); call ls%destroy()
    call disengage_overlay()
  end subroutine

  subroutine test_persistence()
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:), pt(:)
    integer(itb_u64_kind),  allocatable :: ns_comps(:), ds_comps(:), ss_comps(:), ls_comps(:)
    integer(itb_byte_kind), allocatable :: ns_key(:),   ds_key(:),   ss_key(:),   ls_key(:)
    type(itb_seed_t) :: ns, ds, ss, ls
    type(itb_seed_t) :: ns2, ds2, ss2, ls2
    character(*), parameter :: PT_TEXT = "cross-process attach lockseed roundtrip"
    integer :: i

    call engage_overlay()
    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    ! Day 1 -- sender.
    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_seed(ls, "blake3", 1024)
    call ns%attach_lock_seed(ls)

    ns_comps = ns%components(); ds_comps = ds%components()
    ss_comps = ss%components(); ls_comps = ls%components()
    ns_key   = ns%hash_key();   ds_key   = ds%hash_key()
    ss_key   = ss%hash_key();   ls_key   = ls%hash_key()

    ct = itb_encrypt(ns, ds, ss, plaintext)
    call ns%destroy(); call ds%destroy(); call ss%destroy(); call ls%destroy()

    ! Day 2 -- receiver.
    call itb_seed_from_components(ns2, "blake3", ns_comps, ns_key)
    call itb_seed_from_components(ds2, "blake3", ds_comps, ds_key)
    call itb_seed_from_components(ss2, "blake3", ss_comps, ss_key)
    call itb_seed_from_components(ls2, "blake3", ls_comps, ls_key)
    call ns2%attach_lock_seed(ls2)

    pt = itb_decrypt(ns2, ds2, ss2, ct)
    call assert_bytes_eq(TEST_NAME, "persistence roundtrip", pt, plaintext)

    call ns2%destroy(); call ds2%destroy(); call ss2%destroy(); call ls2%destroy()
    call disengage_overlay()
  end subroutine

  subroutine test_self_attach_rejected()
    type(itb_seed_t) :: ns
    integer(itb_status_kind) :: rc
    call new_itb_seed(ns, "blake3", 1024)
    rc = itb_attach_lock_seed_c(ns%raw_handle(), ns%raw_handle())
    call assert_status_eq(TEST_NAME, "self-attach rejected", rc, STATUS_BAD_INPUT)
    call ns%destroy()
  end subroutine

  subroutine test_width_mismatch_rejected()
    type(itb_seed_t) :: ns_256, ls_128
    integer(itb_status_kind) :: rc
    call new_itb_seed(ns_256, "blake3",    1024)  ! width 256
    call new_itb_seed(ls_128, "siphash24", 1024)  ! width 128
    rc = itb_attach_lock_seed_c(ns_256%raw_handle(), ls_128%raw_handle())
    call assert_status_eq(TEST_NAME, "width mismatch rejected", &
                           rc, STATUS_SEED_WIDTH_MIX)
    call ns_256%destroy(); call ls_128%destroy()
  end subroutine

  subroutine test_post_encrypt_attach_rejected()
    type(itb_seed_t) :: ns, ds, ss, ls, ls2
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_byte_kind), allocatable :: ct(:)
    integer(itb_status_kind) :: rc
    character(*), parameter :: PT_TEXT = "pre-switch"
    integer :: i

    call engage_overlay()
    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_seed(ls, "blake3", 1024)
    call ns%attach_lock_seed(ls)

    ! Encrypt once -- locks future attach_lock_seed calls.
    ct = itb_encrypt(ns, ds, ss, plaintext)
    call assert_true(TEST_NAME, "post-encrypt: ct produced", size(ct) > 0)

    call new_itb_seed(ls2, "blake3", 1024)
    rc = itb_attach_lock_seed_c(ns%raw_handle(), ls2%raw_handle())
    call assert_status_eq(TEST_NAME, "post-encrypt re-attach rejected", &
                           rc, STATUS_BAD_INPUT)

    call ns%destroy(); call ds%destroy(); call ss%destroy()
    call ls%destroy(); call ls2%destroy()
    call disengage_overlay()
  end subroutine

  subroutine test_overlay_off_fails_on_encrypt()
    type(itb_seed_t) :: ns, ds, ss, ls
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: scratch(:)
    integer(itb_status_kind) :: rc
    integer(itb_size_kind)   :: out_len
    character(*), parameter :: PT_TEXT = "overlay off - should fail"
    integer :: i

    call itb_set_bit_soup(0)
    call itb_set_lock_soup(0)

    allocate (plaintext(len(PT_TEXT)))
    do i = 1, len(PT_TEXT)
      plaintext(i) = int(iachar(PT_TEXT(i:i)), itb_byte_kind)
    end do

    call new_itb_seed(ns, "blake3", 1024)
    call new_itb_seed(ds, "blake3", 1024)
    call new_itb_seed(ss, "blake3", 1024)
    call new_itb_seed(ls, "blake3", 1024)
    call ns%attach_lock_seed(ls)

    ! With the overlay disengaged the encrypt call surfaces a non-OK
    ! status. Drop to the low-level FFI to observe that status without
    ! terminating the test program.
    allocate (scratch(4096))
    out_len = 0_itb_size_kind
    rc = itb_encrypt_c(ns%raw_handle(), ds%raw_handle(), ss%raw_handle(), &
                        c_loc(plaintext), int(size(plaintext), itb_size_kind), &
                        c_loc(scratch),   int(size(scratch),   itb_size_kind), &
                        out_len)
    call assert_true(TEST_NAME, "overlay-off encrypt fails", rc /= STATUS_OK)

    call ns%destroy(); call ds%destroy(); call ss%destroy(); call ls%destroy()
  end subroutine

end program test_attach_lock_seed
