! itb_cipher.f90 -- low-level free-function cipher entry points.
!
! Mirrors the C binding's `itb_encrypt` / `itb_decrypt` /
! `itb_encrypt_auth` / `itb_decrypt_auth` (Single Ouroboros, 3-seed)
! plus their Triple Ouroboros (7-seed) counterparts.
!
! Single-call path: each function pre-allocates a generous upper bound
! on the output size, calls libitb once, and truncates the result
! array to the actual returned length via `move_alloc` with an
! array-assignment copy. The probe FFI round-trip (NULL pointer +
! cap = 0 discovery call) is skipped; the formula
! `max(131072, ptlen + ptlen/4 + 131072)` covers every cell in the
! mode / nonce-bits / barrier-fill matrix. Under the default
! barrier-fill of 1 the absolute ratio sits at most around 1.155;
! under bf=32 the ratio rises to ~1.346 around the 1 MiB payload
! region, and the 128 KiB pad absorbs the residual margin the
! 1.25x multiplier alone does not cover. Short payloads through
! Triple Ouroboros and the authenticated variants can exhibit
! substantially larger fixed-overhead expansion at very small input
! sizes (Triple + auth-MAC + bf=32 at ptlen=1 ~ 35 KiB); the 128 KiB
! floor handles those without triggering the retry path. The rare
! `STATUS_BUFFER_TOO_SMALL` from the first call surfaces the
! libitb-reported required size in `out_len`, and a single
! resize-and-retry recovers without invoking the explicit two-call
! probe shape. Empty input plaintext / ciphertext is NOT accepted by
! libitb -- the call returns `STATUS_ENCRYPT_FAILED` and the wrapper
! raises via error stop.
!
! Threading: the free-function cipher entry points ARE thread-safe
! when each concurrent invocation uses distinct seed handles and a
! distinct MAC handle (where applicable). Process-wide setters
! (`itb_set_bit_soup` / `itb_set_lock_soup` / `itb_set_max_workers`
! / `itb_set_nonce_bits` / `itb_set_barrier_fill`) snapshot at call
! entry; mutating any of them mid-cipher corrupts the running
! operation -- treat them as set-once-at-startup.

module itb_cipher
  use itb_kinds
  use itb_sys
  use itb_seed,   only: itb_seed_t
  use itb_mac,    only: itb_mac_t
  use itb_errors, only: STATUS_OK, STATUS_BUFFER_TOO_SMALL, raise_itb_error
  implicit none
  private

  public :: itb_encrypt
  public :: itb_decrypt
  public :: itb_encrypt_auth
  public :: itb_decrypt_auth

  public :: itb_encrypt_triple
  public :: itb_decrypt_triple
  public :: itb_encrypt_auth_triple
  public :: itb_decrypt_auth_triple

contains

  ! ----------------------------------------------------------------
  ! Single Ouroboros (3-seed)
  ! ----------------------------------------------------------------

  function itb_encrypt(noise, data, start, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_encrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      ! Pre-allocation was too tight (small payloads through Triple /
      ! authenticated variants can exceed the 1.25x bulk-rate bound).
      ! `out_len` carries the libitb-reported required size; resize
      ! exactly and retry once.
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_encrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                          in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    ! Truncate to actual length via right-sized companion + move_alloc.
    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_decrypt(noise, data, start, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_decrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                        in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_decrypt_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                          in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

  function itb_encrypt_auth(noise, data, start, mac, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_encrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ptlen, &
                              c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_encrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                                mac%raw_handle(), in_ptr, ptlen, &
                                c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_decrypt_auth(noise, data, start, mac, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise, data, start
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                              mac%raw_handle(), in_ptr, ctlen, &
                              c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_decrypt_auth_c(noise%raw_handle(), data%raw_handle(), start%raw_handle(), &
                                mac%raw_handle(), in_ptr, ctlen, &
                                c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

  ! ----------------------------------------------------------------
  ! Triple Ouroboros (7-seed)
  ! ----------------------------------------------------------------

  function itb_encrypt_triple(noise, data1, data2, data3, &
                                start1, start2, start3, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_encrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_encrypt3_c(noise%raw_handle(),                              &
                           data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                           start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                           in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_decrypt_triple(noise, data1, data2, data3, &
                                start1, start2, start3, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_decrypt3_c(noise%raw_handle(),                              &
                         data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                         start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                         in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_decrypt3_c(noise%raw_handle(),                              &
                           data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                           start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                           in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

  function itb_encrypt_auth_triple(noise, data1, data2, data3, &
                                     start1, start2, start3, mac, plaintext) result(ciphertext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: plaintext(:)
    integer(itb_byte_kind), allocatable, target :: ciphertext(:)
    integer(itb_size_kind) :: ptlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ptlen = int(size(plaintext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ptlen > 0) in_ptr = c_loc(plaintext)

    cap = max(131072_itb_size_kind, &
               ptlen + ptlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (ciphertext(cap))

    out_len = 0_itb_size_kind
    rc = itb_encrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (ciphertext)
      allocate (ciphertext(cap))
      rc = itb_encrypt_auth3_c(noise%raw_handle(),                              &
                                data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                                mac%raw_handle(),                                &
                                in_ptr, ptlen, c_loc(ciphertext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = ciphertext(1:out_len)
      call move_alloc(trimmed, ciphertext)
    end block
  end function

  function itb_decrypt_auth_triple(noise, data1, data2, data3, &
                                     start1, start2, start3, mac, ciphertext) result(plaintext)
    type(itb_seed_t),                           intent(in) :: noise
    type(itb_seed_t),                           intent(in) :: data1, data2, data3
    type(itb_seed_t),                           intent(in) :: start1, start2, start3
    type(itb_mac_t),                            intent(in) :: mac
    integer(itb_byte_kind), target, contiguous, intent(in) :: ciphertext(:)
    integer(itb_byte_kind), allocatable, target :: plaintext(:)
    integer(itb_size_kind) :: ctlen, cap, out_len
    integer(itb_status_kind) :: rc
    type(c_ptr) :: in_ptr

    ctlen = int(size(ciphertext), itb_size_kind)
    in_ptr = c_null_ptr
    if (ctlen > 0) in_ptr = c_loc(ciphertext)

    cap = max(131072_itb_size_kind, &
               ctlen + ctlen / 4_itb_size_kind + 131072_itb_size_kind)
    allocate (plaintext(cap))

    out_len = 0_itb_size_kind
    rc = itb_decrypt_auth3_c(noise%raw_handle(),                              &
                              data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                              start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                              mac%raw_handle(),                                &
                              in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    if (rc == STATUS_BUFFER_TOO_SMALL) then
      cap = out_len
      deallocate (plaintext)
      allocate (plaintext(cap))
      rc = itb_decrypt_auth3_c(noise%raw_handle(),                              &
                                data1%raw_handle(),  data2%raw_handle(),  data3%raw_handle(), &
                                start1%raw_handle(), start2%raw_handle(), start3%raw_handle(),&
                                mac%raw_handle(),                                &
                                in_ptr, ctlen, c_loc(plaintext), cap, out_len)
    end if
    if (rc /= STATUS_OK) call raise_itb_error(rc)

    block
      integer(itb_byte_kind), allocatable :: trimmed(:)
      allocate (trimmed(out_len))
      trimmed = plaintext(1:out_len)
      call move_alloc(trimmed, plaintext)
    end block
  end function

end module itb_cipher
