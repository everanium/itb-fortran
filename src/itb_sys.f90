! itb_sys.f90 -- raw `interface ... bind(C)` declarations for every
! libitb C-ABI export. There are 93 entry points across these surfaces:
!
!   * version + hash + MAC registries        (10 declarations)
!   * process-wide setters / getters         (10 declarations)
!   * Seeds                                  ( 8 declarations)
!   * MACs                                   ( 2 declarations beyond registry)
!   * cipher Single + Triple +/- auth        ( 8 declarations)
!   * `ITB_Easy_*` Encryptor                 (28 declarations)
!   * `ITB_Blob_*` persistence               (18 declarations)
!   * miscellaneous (chunk-len + sizes)      ( 4 declarations)
!   * AttachLockSeed                         ( 1 declaration)
!
! The conventions:
!
!   * `int` (status, scalar) → `integer(c_int)`.
!   * `size_t` (size, length) → `integer(c_size_t)`.
!   * `uintptr_t` (opaque handle) → `integer(c_intptr_t)`.
!   * `void *`, `char *`, `uint8_t *`, `uint64_t *` (any pointer
!     parameter) → `type(c_ptr), value`. The wrapper layer passes
!     `c_loc(buffer)` to populate the pointer; this keeps the raw
!     interface oblivious to the buffer's element kind.
!   * Output scalars (`int *outStatus`, `size_t *outLen`) -> declared
!     by-reference (no `value` attribute) per F2003 interop semantics
!     -- `bind(C)` automatically maps a non-VALUE Fortran scalar to a
!     C pointer-to-scalar.
!
! Higher-level modules (`itb_seed`, `itb_mac`, `itb_encryptor`,
! `itb_blob`, `itb_cipher`, `itb_streams`, `itb_library`) layer
! safe wrappers on top of these declarations -- those modules import
! `itb_kinds` (semantic-named KINDs) and `itb_sys` (raw FFI), and
! perform NUL-strip / NUL-append / `c_loc` bridging.

module itb_sys
  use, intrinsic :: iso_c_binding
  implicit none
  public

  interface

    ! --------------------------------------------------------------
    ! Version + hash + MAC registries
    ! --------------------------------------------------------------

    function itb_version_c(out, capBytes, outLen) bind(C, name="ITB_Version") result(rc)
      import
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_last_error_c(out, capBytes, outLen) bind(C, name="ITB_LastError") result(rc)
      import
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_hash_count_c() bind(C, name="ITB_HashCount") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_hash_name_c(i, out, capBytes, outLen) bind(C, name="ITB_HashName") result(rc)
      import
      integer(c_int), value      :: i
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_hash_width_c(i) bind(C, name="ITB_HashWidth") result(w)
      import
      integer(c_int), value      :: i
      integer(c_int)             :: w
    end function

    function itb_mac_count_c() bind(C, name="ITB_MACCount") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_mac_name_c(i, out, capBytes, outLen) bind(C, name="ITB_MACName") result(rc)
      import
      integer(c_int), value      :: i
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_mac_key_size_c(i) bind(C, name="ITB_MACKeySize") result(n)
      import
      integer(c_int), value      :: i
      integer(c_int)             :: n
    end function

    function itb_mac_tag_size_c(i) bind(C, name="ITB_MACTagSize") result(n)
      import
      integer(c_int), value      :: i
      integer(c_int)             :: n
    end function

    function itb_mac_min_key_bytes_c(i) bind(C, name="ITB_MACMinKeyBytes") result(n)
      import
      integer(c_int), value      :: i
      integer(c_int)             :: n
    end function

    ! --------------------------------------------------------------
    ! Process-wide setters / getters (10)
    ! --------------------------------------------------------------

    function itb_set_bit_soup_c(mode) bind(C, name="ITB_SetBitSoup") result(rc)
      import
      integer(c_int), value      :: mode
      integer(c_int)             :: rc
    end function

    function itb_get_bit_soup_c() bind(C, name="ITB_GetBitSoup") result(mode)
      import
      integer(c_int)             :: mode
    end function

    function itb_set_lock_soup_c(mode) bind(C, name="ITB_SetLockSoup") result(rc)
      import
      integer(c_int), value      :: mode
      integer(c_int)             :: rc
    end function

    function itb_get_lock_soup_c() bind(C, name="ITB_GetLockSoup") result(mode)
      import
      integer(c_int)             :: mode
    end function

    function itb_set_lock_batch_c(mode) bind(C, name="ITB_SetLockBatch") result(rc)
      import
      integer(c_int), value      :: mode
      integer(c_int)             :: rc
    end function

    function itb_get_lock_batch_c() bind(C, name="ITB_GetLockBatch") result(mode)
      import
      integer(c_int)             :: mode
    end function

    function itb_set_max_workers_c(n) bind(C, name="ITB_SetMaxWorkers") result(rc)
      import
      integer(c_int), value      :: n
      integer(c_int)             :: rc
    end function

    function itb_get_max_workers_c() bind(C, name="ITB_GetMaxWorkers") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_set_nonce_bits_c(n) bind(C, name="ITB_SetNonceBits") result(rc)
      import
      integer(c_int), value      :: n
      integer(c_int)             :: rc
    end function

    function itb_get_nonce_bits_c() bind(C, name="ITB_GetNonceBits") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_set_barrier_fill_c(n) bind(C, name="ITB_SetBarrierFill") result(rc)
      import
      integer(c_int), value      :: n
      integer(c_int)             :: rc
    end function

    function itb_get_barrier_fill_c() bind(C, name="ITB_GetBarrierFill") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_set_memory_limit_c(limit) bind(C, name="ITB_SetMemoryLimit") result(prev)
      import
      integer(c_int64_t), value  :: limit
      integer(c_int64_t)         :: prev
    end function

    function itb_set_gc_percent_c(pct) bind(C, name="ITB_SetGCPercent") result(prev)
      import
      integer(c_int), value      :: pct
      integer(c_int)             :: prev
    end function

    ! --------------------------------------------------------------
    ! Sizes + chunk-length parser
    ! --------------------------------------------------------------

    function itb_max_key_bits_c() bind(C, name="ITB_MaxKeyBits") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_channels_c() bind(C, name="ITB_Channels") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_header_size_c() bind(C, name="ITB_HeaderSize") result(n)
      import
      integer(c_int)             :: n
    end function

    function itb_parse_chunk_len_c(header, headerLen, outChunkLen) &
        bind(C, name="ITB_ParseChunkLen") result(rc)
      import
      type(c_ptr), value         :: header
      integer(c_size_t), value   :: headerLen
      integer(c_size_t)          :: outChunkLen
      integer(c_int)             :: rc
    end function

    ! --------------------------------------------------------------
    ! Seeds (low-level)
    ! --------------------------------------------------------------

    function itb_new_seed_c(hashName, keyBits, outHandle) bind(C, name="ITB_NewSeed") result(rc)
      import
      type(c_ptr), value             :: hashName
      integer(c_int), value          :: keyBits
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_free_seed_c(handle) bind(C, name="ITB_FreeSeed") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: rc
    end function

    function itb_seed_width_c(handle, outStatus) bind(C, name="ITB_SeedWidth") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: outStatus
      integer(c_int)                 :: rc
    end function

    function itb_seed_hash_name_c(handle, out, capBytes, outLen) &
        bind(C, name="ITB_SeedHashName") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      type(c_ptr), value             :: out
      integer(c_size_t), value       :: capBytes
      integer(c_size_t)              :: outLen
      integer(c_int)                 :: rc
    end function

    function itb_new_seed_from_components_c(hashName, components, componentsLen, &
                                             hashKey, hashKeyLen, outHandle) &
        bind(C, name="ITB_NewSeedFromComponents") result(rc)
      import
      type(c_ptr), value             :: hashName
      type(c_ptr), value             :: components
      integer(c_int), value          :: componentsLen
      type(c_ptr), value             :: hashKey
      integer(c_int), value          :: hashKeyLen
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_get_seed_hash_key_c(handle, out, capBytes, outLen) &
        bind(C, name="ITB_GetSeedHashKey") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      type(c_ptr), value             :: out
      integer(c_size_t), value       :: capBytes
      integer(c_size_t)              :: outLen
      integer(c_int)                 :: rc
    end function

    function itb_get_seed_components_c(handle, out, capCount, outLen) &
        bind(C, name="ITB_GetSeedComponents") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      type(c_ptr), value             :: out
      integer(c_int), value          :: capCount
      integer(c_int)                 :: outLen
      integer(c_int)                 :: rc
    end function

    function itb_attach_lock_seed_c(noiseHandle, lockHandle) &
        bind(C, name="ITB_AttachLockSeed") result(rc)
      import
      integer(c_intptr_t), value     :: noiseHandle
      integer(c_intptr_t), value     :: lockHandle
      integer(c_int)                 :: rc
    end function

    ! --------------------------------------------------------------
    ! MACs
    ! --------------------------------------------------------------

    function itb_new_mac_c(macName, key, keyLen, outHandle) bind(C, name="ITB_NewMAC") result(rc)
      import
      type(c_ptr), value             :: macName
      type(c_ptr), value             :: key
      integer(c_size_t), value       :: keyLen
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_free_mac_c(handle) bind(C, name="ITB_FreeMAC") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: rc
    end function

    ! --------------------------------------------------------------
    ! Cipher Single + Triple +/- auth
    ! --------------------------------------------------------------

    function itb_encrypt_c(noise, data, start, plaintext, ptlen, out, outCap, outLen) &
        bind(C, name="ITB_Encrypt") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt_c(noise, data, start, ciphertext, ctlen, out, outCap, outLen) &
        bind(C, name="ITB_Decrypt") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt3_c(noise, data1, data2, data3, start1, start2, start3, &
                             plaintext, ptlen, out, outCap, outLen) &
        bind(C, name="ITB_Encrypt3") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3, start1, start2, start3
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt3_c(noise, data1, data2, data3, start1, start2, start3, &
                             ciphertext, ctlen, out, outCap, outLen) &
        bind(C, name="ITB_Decrypt3") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3, start1, start2, start3
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_auth_c(noise, data, start, mac, plaintext, ptlen, &
                                 out, outCap, outLen) &
        bind(C, name="ITB_EncryptAuth") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt_auth_c(noise, data, start, mac, ciphertext, ctlen, &
                                 out, outCap, outLen) &
        bind(C, name="ITB_DecryptAuth") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_auth3_c(noise, data1, data2, data3, start1, start2, start3, mac, &
                                  plaintext, ptlen, out, outCap, outLen) &
        bind(C, name="ITB_EncryptAuth3") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3, start1, start2, start3, mac
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt_auth3_c(noise, data1, data2, data3, start1, start2, start3, mac, &
                                  ciphertext, ctlen, out, outCap, outLen) &
        bind(C, name="ITB_DecryptAuth3") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3, start1, start2, start3, mac
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    ! --------------------------------------------------------------
    ! Easy Mode encryptor
    ! --------------------------------------------------------------

    function itb_easy_new_c(primitive, keyBits, macName, mode, outHandle) &
        bind(C, name="ITB_Easy_New") result(rc)
      import
      type(c_ptr), value             :: primitive, macName
      integer(c_int), value          :: keyBits, mode
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_easy_new_mixed_c(primN, primD, primS, primL, keyBits, macName, outHandle) &
        bind(C, name="ITB_Easy_NewMixed") result(rc)
      import
      type(c_ptr), value             :: primN, primD, primS, primL, macName
      integer(c_int), value          :: keyBits
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_easy_new_mixed3_c(primN, primD1, primD2, primD3, &
                                    primS1, primS2, primS3, primL, &
                                    keyBits, macName, outHandle) &
        bind(C, name="ITB_Easy_NewMixed3") result(rc)
      import
      type(c_ptr), value             :: primN, primD1, primD2, primD3
      type(c_ptr), value             :: primS1, primS2, primS3, primL, macName
      integer(c_int), value          :: keyBits
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_easy_free_c(handle) bind(C, name="ITB_Easy_Free") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: rc
    end function

    function itb_easy_close_c(handle) bind(C, name="ITB_Easy_Close") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: rc
    end function

    function itb_easy_encrypt_c(handle, plaintext, ptlen, out, outCap, outLen) &
        bind(C, name="ITB_Easy_Encrypt") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_decrypt_c(handle, ciphertext, ctlen, out, outCap, outLen) &
        bind(C, name="ITB_Easy_Decrypt") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_encrypt_auth_c(handle, plaintext, ptlen, out, outCap, outLen) &
        bind(C, name="ITB_Easy_EncryptAuth") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: plaintext, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_decrypt_auth_c(handle, ciphertext, ctlen, out, outCap, outLen) &
        bind(C, name="ITB_Easy_DecryptAuth") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: ciphertext, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_set_nonce_bits_c(handle, n) &
        bind(C, name="ITB_Easy_SetNonceBits") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: n
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_barrier_fill_c(handle, n) &
        bind(C, name="ITB_Easy_SetBarrierFill") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: n
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_bit_soup_c(handle, mode) &
        bind(C, name="ITB_Easy_SetBitSoup") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: mode
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_lock_soup_c(handle, mode) &
        bind(C, name="ITB_Easy_SetLockSoup") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: mode
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_lock_batch_c(handle, mode) &
        bind(C, name="ITB_Easy_SetLockBatch") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: mode
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_lock_seed_c(handle, mode) &
        bind(C, name="ITB_Easy_SetLockSeed") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: mode
      integer(c_int)                 :: rc
    end function

    function itb_easy_set_chunk_size_c(handle, n) &
        bind(C, name="ITB_Easy_SetChunkSize") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int), value          :: n
      integer(c_int)                 :: rc
    end function

    function itb_easy_primitive_c(handle, out, capBytes, outLen) &
        bind(C, name="ITB_Easy_Primitive") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_primitive_at_c(handle, slot, out, capBytes, outLen) &
        bind(C, name="ITB_Easy_PrimitiveAt") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_key_bits_c(handle, outStatus) &
        bind(C, name="ITB_Easy_KeyBits") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_mode_c(handle, outStatus) &
        bind(C, name="ITB_Easy_Mode") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_mac_name_c(handle, out, capBytes, outLen) &
        bind(C, name="ITB_Easy_MACName") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_seed_count_c(handle, outStatus) &
        bind(C, name="ITB_Easy_SeedCount") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_seed_components_c(handle, slot, out, capCount, outLen) &
        bind(C, name="ITB_Easy_SeedComponents") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot, capCount
      type(c_ptr), value         :: out
      integer(c_int)             :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_has_prf_keys_c(handle, outStatus) &
        bind(C, name="ITB_Easy_HasPRFKeys") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_prf_key_c(handle, slot, out, capBytes, outLen) &
        bind(C, name="ITB_Easy_PRFKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_mac_key_c(handle, out, capBytes, outLen) &
        bind(C, name="ITB_Easy_MACKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_export_c(handle, out, outCap, outLen) &
        bind(C, name="ITB_Easy_Export") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_import_c(handle, blob, blobLen) &
        bind(C, name="ITB_Easy_Import") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: blob
      integer(c_size_t), value   :: blobLen
      integer(c_int)             :: rc
    end function

    function itb_easy_peek_config_c(blob, blobLen, primOut, primCap, primLen, &
                                     keyBitsOut, modeOut, &
                                     macOut, macCap, macLen) &
        bind(C, name="ITB_Easy_PeekConfig") result(rc)
      import
      type(c_ptr), value         :: blob, primOut, macOut
      integer(c_size_t), value   :: blobLen, primCap, macCap
      integer(c_size_t)          :: primLen, macLen
      integer(c_int)             :: keyBitsOut, modeOut
      integer(c_int)             :: rc
    end function

    function itb_easy_last_mismatch_field_c(out, capBytes, outLen) &
        bind(C, name="ITB_Easy_LastMismatchField") result(rc)
      import
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: capBytes
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_nonce_bits_c(handle, outStatus) &
        bind(C, name="ITB_Easy_NonceBits") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_header_size_c(handle, outStatus) &
        bind(C, name="ITB_Easy_HeaderSize") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_easy_parse_chunk_len_c(handle, header, headerLen, outChunkLen) &
        bind(C, name="ITB_Easy_ParseChunkLen") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: header
      integer(c_size_t), value   :: headerLen
      integer(c_size_t)          :: outChunkLen
      integer(c_int)             :: rc
    end function

    function itb_easy_is_mixed_c(handle, outStatus) &
        bind(C, name="ITB_Easy_IsMixed") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    ! --------------------------------------------------------------
    ! Blobs (per-seed material persistence)
    ! --------------------------------------------------------------

    function itb_blob128_new_c(outHandle) bind(C, name="ITB_Blob128_New") result(rc)
      import
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_blob256_new_c(outHandle) bind(C, name="ITB_Blob256_New") result(rc)
      import
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_blob512_new_c(outHandle) bind(C, name="ITB_Blob512_New") result(rc)
      import
      integer(c_intptr_t)            :: outHandle
      integer(c_int)                 :: rc
    end function

    function itb_blob_free_c(handle) bind(C, name="ITB_Blob_Free") result(rc)
      import
      integer(c_intptr_t), value     :: handle
      integer(c_int)                 :: rc
    end function

    function itb_blob_width_c(handle, outStatus) &
        bind(C, name="ITB_Blob_Width") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_blob_mode_c(handle, outStatus) &
        bind(C, name="ITB_Blob_Mode") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: outStatus
      integer(c_int)             :: rc
    end function

    function itb_blob_set_key_c(handle, slot, key, keyLen) &
        bind(C, name="ITB_Blob_SetKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: key
      integer(c_size_t), value   :: keyLen
      integer(c_int)             :: rc
    end function

    function itb_blob_get_key_c(handle, slot, out, outCap, outLen) &
        bind(C, name="ITB_Blob_GetKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_blob_set_components_c(handle, slot, comps, count) &
        bind(C, name="ITB_Blob_SetComponents") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: comps
      integer(c_size_t), value   :: count
      integer(c_int)             :: rc
    end function

    function itb_blob_get_components_c(handle, slot, out, outCap, outCount) &
        bind(C, name="ITB_Blob_GetComponents") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: slot
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outCount
      integer(c_int)             :: rc
    end function

    function itb_blob_set_mac_key_c(handle, key, keyLen) &
        bind(C, name="ITB_Blob_SetMACKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: key
      integer(c_size_t), value   :: keyLen
      integer(c_int)             :: rc
    end function

    function itb_blob_get_mac_key_c(handle, out, outCap, outLen) &
        bind(C, name="ITB_Blob_GetMACKey") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_blob_set_mac_name_c(handle, name, nameLen) &
        bind(C, name="ITB_Blob_SetMACName") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: name
      integer(c_size_t), value   :: nameLen
      integer(c_int)             :: rc
    end function

    function itb_blob_get_mac_name_c(handle, out, outCap, outLen) &
        bind(C, name="ITB_Blob_GetMACName") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_blob_export_c(handle, optsBitmask, out, outCap, outLen) &
        bind(C, name="ITB_Blob_Export") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: optsBitmask
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_blob_export3_c(handle, optsBitmask, out, outCap, outLen) &
        bind(C, name="ITB_Blob_Export3") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int), value      :: optsBitmask
      type(c_ptr), value         :: out
      integer(c_size_t), value   :: outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_blob_import_c(handle, blob, blobLen) &
        bind(C, name="ITB_Blob_Import") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: blob
      integer(c_size_t), value   :: blobLen
      integer(c_int)             :: rc
    end function

    function itb_blob_import3_c(handle, blob, blobLen) &
        bind(C, name="ITB_Blob_Import3") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: blob
      integer(c_size_t), value   :: blobLen
      integer(c_int)             :: rc
    end function

    ! --------------------------------------------------------------
    ! Streaming AEAD per-chunk ABI exports
    !
    ! These dispatch a single chunk through the Streaming AEAD
    ! pipeline: the (streamID, cumulativePixelOffset, finalFlag)
    ! binding tuple is folded into the MAC input alongside the
    ! per-chunk plaintext / ciphertext. The 128 / 256 / 512 entry
    ! points are kept distinct for ABI symmetry; the underlying
    ! capi handler dispatches by the seeds' native hash width.
    ! --------------------------------------------------------------

    function itb_encrypt_stream_authenticated128_c(noise, data, start, mac, &
                                                     plaintext, ptlen,        &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     finalFlag,                 &
                                                     out, outCap, outLen)      &
        bind(C, name="ITB_EncryptStreamAuthenticated128") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_stream_authenticated256_c(noise, data, start, mac, &
                                                     plaintext, ptlen,        &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     finalFlag,                 &
                                                     out, outCap, outLen)      &
        bind(C, name="ITB_EncryptStreamAuthenticated256") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_stream_authenticated512_c(noise, data, start, mac, &
                                                     plaintext, ptlen,        &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     finalFlag,                 &
                                                     out, outCap, outLen)      &
        bind(C, name="ITB_EncryptStreamAuthenticated512") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated128_c(noise, data, start, mac, &
                                                     ciphertext, ctlen,       &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     out, outCap, outLen,       &
                                                     finalFlagOut)              &
        bind(C, name="ITB_DecryptStreamAuthenticated128") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated256_c(noise, data, start, mac, &
                                                     ciphertext, ctlen,       &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     out, outCap, outLen,       &
                                                     finalFlagOut)              &
        bind(C, name="ITB_DecryptStreamAuthenticated256") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated512_c(noise, data, start, mac, &
                                                     ciphertext, ctlen,       &
                                                     streamID,                 &
                                                     cumulativePixelOffset,    &
                                                     out, outCap, outLen,       &
                                                     finalFlagOut)              &
        bind(C, name="ITB_DecryptStreamAuthenticated512") result(rc)
      import
      integer(c_intptr_t), value :: noise, data, start, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_encrypt_stream_authenticated3x128_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                plaintext, ptlen, streamID, cumulativePixelOffset,           &
                finalFlag, out, outCap, outLen)                              &
        bind(C, name="ITB_EncryptStreamAuthenticated3x128") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_stream_authenticated3x256_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                plaintext, ptlen, streamID, cumulativePixelOffset,           &
                finalFlag, out, outCap, outLen)                              &
        bind(C, name="ITB_EncryptStreamAuthenticated3x256") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_encrypt_stream_authenticated3x512_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                plaintext, ptlen, streamID, cumulativePixelOffset,           &
                finalFlag, out, outCap, outLen)                              &
        bind(C, name="ITB_EncryptStreamAuthenticated3x512") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated3x128_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                ciphertext, ctlen, streamID, cumulativePixelOffset,          &
                out, outCap, outLen, finalFlagOut)                           &
        bind(C, name="ITB_DecryptStreamAuthenticated3x128") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated3x256_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                ciphertext, ctlen, streamID, cumulativePixelOffset,          &
                out, outCap, outLen, finalFlagOut)                           &
        bind(C, name="ITB_DecryptStreamAuthenticated3x256") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_decrypt_stream_authenticated3x512_c(                       &
                noise, data1, data2, data3, start1, start2, start3, mac,    &
                ciphertext, ctlen, streamID, cumulativePixelOffset,          &
                out, outCap, outLen, finalFlagOut)                           &
        bind(C, name="ITB_DecryptStreamAuthenticated3x512") result(rc)
      import
      integer(c_intptr_t), value :: noise, data1, data2, data3
      integer(c_intptr_t), value :: start1, start2, start3, mac
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    function itb_easy_encrypt_stream_auth_c(handle, plaintext, ptlen,        &
                                              streamID, cumulativePixelOffset,&
                                              finalFlag, out, outCap, outLen) &
        bind(C, name="ITB_Easy_EncryptStreamAuth") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: plaintext, streamID, out
      integer(c_size_t), value   :: ptlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_int), value      :: finalFlag
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_easy_decrypt_stream_auth_c(handle, ciphertext, ctlen,       &
                                              streamID, cumulativePixelOffset,&
                                              out, outCap, outLen,            &
                                              finalFlagOut)                    &
        bind(C, name="ITB_Easy_DecryptStreamAuth") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: ciphertext, streamID, out
      integer(c_size_t), value   :: ctlen, outCap
      integer(c_int64_t), value  :: cumulativePixelOffset
      integer(c_size_t)          :: outLen
      integer(c_int)             :: finalFlagOut
      integer(c_int)             :: rc
    end function

    ! --------------------------------------------------------------
    ! Format-deniability wrapper (outer CTR cipher)
    !
    ! These twelve declarations bind to the libitb wrapper exports
    ! defined in `cmd/cshared/main.go` under the
    ! "Format-deniability wrapper" section. Every entry point
    ! dispatches off a `cipher_name` NUL-terminated string.
    ! The Fortran-side wrapper module `itb_wrapper` layers
    ! a derived-type / subroutine surface on top.
    ! --------------------------------------------------------------

    function itb_wrapper_key_size_c(cipherName, outSize) &
        bind(C, name="ITB_WrapperKeySize") result(rc)
      import
      type(c_ptr), value         :: cipherName
      integer(c_size_t)          :: outSize
      integer(c_int)             :: rc
    end function

    function itb_wrapper_nonce_size_c(cipherName, outSize) &
        bind(C, name="ITB_WrapperNonceSize") result(rc)
      import
      type(c_ptr), value         :: cipherName
      integer(c_size_t)          :: outSize
      integer(c_int)             :: rc
    end function

    function itb_wrapper_derive_key_c(cipherName, master, masterLen, &
                                        out, outCap, outLen) &
        bind(C, name="ITB_WrapperDeriveKey") result(rc)
      import
      type(c_ptr), value         :: cipherName, master, out
      integer(c_size_t), value   :: masterLen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_wrap_c(cipherName, key, keyLen, blob, blobLen, &
                          out, outCap, outLen) &
        bind(C, name="ITB_Wrap") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, blob, out
      integer(c_size_t), value   :: keyLen, blobLen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_unwrap_c(cipherName, key, keyLen, wire, wireLen, &
                            out, outCap, outLen) &
        bind(C, name="ITB_Unwrap") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, wire, out
      integer(c_size_t), value   :: keyLen, wireLen, outCap
      integer(c_size_t)          :: outLen
      integer(c_int)             :: rc
    end function

    function itb_wrap_in_place_c(cipherName, key, keyLen, blob, blobLen, &
                                    outNonce, nonceCap) &
        bind(C, name="ITB_WrapInPlace") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, blob, outNonce
      integer(c_size_t), value   :: keyLen, blobLen, nonceCap
      integer(c_int)             :: rc
    end function

    function itb_unwrap_in_place_c(cipherName, key, keyLen, wire, wireLen) &
        bind(C, name="ITB_UnwrapInPlace") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, wire
      integer(c_size_t), value   :: keyLen, wireLen
      integer(c_int)             :: rc
    end function

    function itb_wrap_stream_writer_init_c(cipherName, key, keyLen,    &
                                             outNonce, nonceCap, outHandle) &
        bind(C, name="ITB_WrapStreamWriter_Init") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, outNonce
      integer(c_size_t), value   :: keyLen, nonceCap
      integer(c_intptr_t)        :: outHandle
      integer(c_int)             :: rc
    end function

    function itb_wrap_stream_writer_update_c(handle, src, srcLen, dst, dstCap) &
        bind(C, name="ITB_WrapStreamWriter_Update") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src, dst
      integer(c_size_t), value   :: srcLen, dstCap
      integer(c_int)             :: rc
    end function

    function itb_wrap_stream_writer_free_c(handle) &
        bind(C, name="ITB_WrapStreamWriter_Free") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: rc
    end function

    function itb_unwrap_stream_reader_init_c(cipherName, key, keyLen,   &
                                               wireNonce, nonceLen, outHandle) &
        bind(C, name="ITB_UnwrapStreamReader_Init") result(rc)
      import
      type(c_ptr), value         :: cipherName, key, wireNonce
      integer(c_size_t), value   :: keyLen, nonceLen
      integer(c_intptr_t)        :: outHandle
      integer(c_int)             :: rc
    end function

    function itb_unwrap_stream_reader_update_c(handle, src, srcLen, dst, dstCap) &
        bind(C, name="ITB_UnwrapStreamReader_Update") result(rc)
      import
      integer(c_intptr_t), value :: handle
      type(c_ptr), value         :: src, dst
      integer(c_size_t), value   :: srcLen, dstCap
      integer(c_int)             :: rc
    end function

    function itb_unwrap_stream_reader_free_c(handle) &
        bind(C, name="ITB_UnwrapStreamReader_Free") result(rc)
      import
      integer(c_intptr_t), value :: handle
      integer(c_int)             :: rc
    end function

  end interface

end module itb_sys
