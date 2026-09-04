! itb_pipeline.f90 -- the Triple Pipeline handle wrapper.
!
! One itb_pipeline_t replaces the 8-seed + parallax + wrapper +
! MAC ceremony of the low-level path. The Pipeline is initialised
! against a profile name (an opaque string validated by Go) plus an
! optional itb_opts_t override builder, or loaded from a session
! blob produced by itb_pipeline_save / itb_pipeline_rekey.
!
! Lifetime discipline (Fortran has no destructors): every successful
! itb_pipeline_init / itb_pipeline_load / itb_pipeline_load_f must
! be paired with exactly one itb_pipeline_free call. itb_pipeline_close zeroes the key
! material early (idempotent; subsequent cipher calls return
! ITB_STATUS_TRIPLE_CLOSED) but the handle itself is released only by
! itb_pipeline_free, which internally closes first.
!
! Bytes cross the surface as integer(c_int8_t) arrays. Output arrays
! are allocated by the callee to the exact produced length.

module itb_pipeline
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t, c_size_t, &
      c_intptr_t, c_char, c_ptr, c_loc, c_null_ptr
  use itb_status
  use itb_ffi
  use itb_error
  use itb_opts
  implicit none
  private

  public :: itb_pipeline_t
  public :: itb_pipeline_init, itb_pipeline_load, itb_pipeline_load_f
  public :: itb_pipeline_save, itb_pipeline_save_f, itb_pipeline_max_workers
  public :: itb_pipeline_rekey
  public :: itb_pipeline_close, itb_pipeline_free
  public :: itb_encrypt_message, itb_decrypt_message
  public :: itb_encrypt_stream_one_shot, itb_decrypt_stream_one_shot
  public :: itb_encrypt_message_into, itb_decrypt_message_into
  public :: itb_encrypt_stream_one_shot_into, itb_decrypt_stream_one_shot_into
  public :: itb_inspect, itb_register, itb_lookup, itb_profiles

  type :: itb_pipeline_t
    integer(c_intptr_t) :: handle = 0_c_intptr_t
  end type

  ! Floor capacity for blob / JSON output buffers (Init / Rekey /
  ! Save / Inspect / Lookup / Profiles).
  integer, parameter :: BLOB_CAP = 65536

  ! Caller-allocated-buffer selectors for the shared retry-once body.
  integer, parameter :: BUF_INIT     = 1
  integer, parameter :: BUF_SAVE     = 2
  integer, parameter :: BUF_REKEY    = 3
  integer, parameter :: BUF_INSPECT  = 4
  integer, parameter :: BUF_LOOKUP   = 5
  integer, parameter :: BUF_PROFILES = 6

  ! Cipher-path selectors for the shared dispatch body.
  integer, parameter :: OP_ENCRYPT_MESSAGE = 1
  integer, parameter :: OP_DECRYPT_MESSAGE = 2
  integer, parameter :: OP_ENCRYPT_STREAM  = 3
  integer, parameter :: OP_DECRYPT_STREAM  = 4

contains

  ! Constructs a fresh Pipeline against the named profile. On a
  ! blob-buffer retry the Init re-runs and yields a fresh session (the
  ! undersized attempt is closed by libitb before returning). The Init
  ! blob is not retained binding-side; itb_pipeline_save reads the
  ! current bytes from libitb.
  subroutine itb_pipeline_init(pipe, profile, opts, err)
    type(itb_pipeline_t), intent(out) :: pipe
    character(*), intent(in)          :: profile
    type(itb_opts_t), intent(in)      :: opts
    type(itb_error_t), intent(out)    :: err
    character(kind=c_char), allocatable, target :: c_prof(:), c_opts(:)
    integer(c_int8_t), allocatable :: blob(:)
    integer(c_intptr_t) :: handle

    call itb_to_cstr(profile, c_prof)
    call itb_to_cstr(itb_opts_query(opts), c_opts)
    handle = 0_c_intptr_t
    call buffer_call(BUF_INIT, blob, err, handle=handle, &
        p1=c_loc(c_prof(1)), p2=c_loc(c_opts(1)))
    if (.not. itb_ok(err)) return
    pipe%handle = handle
  end subroutine

  ! Reconstructs a Pipeline from a blob produced by itb_pipeline_save
  ! or itb_pipeline_rekey. The profile shape travels inside the blob
  ! -- no profile name, no opts. Omit perm_master / wrap_master to use
  ! the blob-embedded masters; pass both to override them (the pair
  ! is validated by libitb). A blob whose record names a primitive
  ! absent from the local build returns
  ! ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN; a record failing the profile
  ! field rules ITB_STATUS_BLOB_MALFORMED_RECIPE.
  subroutine itb_pipeline_load(pipe, blob, err, perm_master, wrap_master)
    type(itb_pipeline_t), intent(out)                        :: pipe
    integer(c_int8_t), intent(in), target, contiguous        :: blob(:)
    type(itb_error_t), intent(out)                           :: err
    integer(c_int8_t), intent(in), target, contiguous, optional :: perm_master(:)
    integer(c_int8_t), intent(in), target, contiguous, optional :: wrap_master(:)
    type(c_ptr)         :: blob_p, pm_p, wm_p
    integer(c_size_t)   :: pm_len, wm_len, masters
    integer(c_intptr_t) :: handle
    integer(c_int)      :: rc

    call masters_args(perm_master, wrap_master, pm_p, pm_len, wm_p, wm_len, masters)
    blob_p = c_null_ptr
    if (size(blob) > 0) blob_p = c_loc(blob(1))
    handle = 0_c_intptr_t
    rc = c_itb_triple_load(blob_p, int(size(blob), c_size_t), &
        pm_p, pm_len, wm_p, wm_len, masters, handle)
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    pipe%handle = handle
  end subroutine

  ! itb_pipeline_load for a blob stored at path; the file is read
  ! inside libitb (a missing or unreadable file is
  ! ITB_STATUS_BAD_INPUT with the diagnostic in err%message).
  subroutine itb_pipeline_load_f(pipe, path, err, perm_master, wrap_master)
    type(itb_pipeline_t), intent(out)                        :: pipe
    character(*), intent(in)                                 :: path
    type(itb_error_t), intent(out)                           :: err
    integer(c_int8_t), intent(in), target, contiguous, optional :: perm_master(:)
    integer(c_int8_t), intent(in), target, contiguous, optional :: wrap_master(:)
    character(kind=c_char), allocatable, target :: c_path(:)
    type(c_ptr)         :: pm_p, wm_p
    integer(c_size_t)   :: pm_len, wm_len, masters
    integer(c_intptr_t) :: handle
    integer(c_int)      :: rc

    call masters_args(perm_master, wrap_master, pm_p, pm_len, wm_p, wm_len, masters)
    call itb_to_cstr(path, c_path)
    handle = 0_c_intptr_t
    rc = c_itb_triple_load_f(c_loc(c_path(1)), pm_p, pm_len, wm_p, wm_len, &
        masters, handle)
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    pipe%handle = handle
  end subroutine

  ! The current session-bundle blob for the receiver side (the init
  ! blob, or the bytes of the latest rekey). A closed handle returns
  ! ITB_STATUS_TRIPLE_CLOSED.
  subroutine itb_pipeline_save(pipe, blob, err)
    type(itb_pipeline_t), intent(in)            :: pipe
    integer(c_int8_t), allocatable, intent(out) :: blob(:)
    type(itb_error_t), intent(out)              :: err
    integer(c_intptr_t) :: h

    h = pipe%handle
    call buffer_call(BUF_SAVE, blob, err, handle=h)
  end subroutine

  ! Writes the current blob to path inside libitb (mode 0600; the
  ! containing directory must exist).
  subroutine itb_pipeline_save_f(pipe, path, err)
    type(itb_pipeline_t), intent(in) :: pipe
    character(*), intent(in)         :: path
    type(itb_error_t), intent(out)   :: err
    character(kind=c_char), allocatable, target :: c_path(:)

    call itb_to_cstr(path, c_path)
    call itb_error_set(err, c_itb_triple_save_f(pipe%handle, c_loc(c_path(1))))
  end subroutine

  ! Sets the worker cap for every subsequent cipher call. n is clamped
  ! by libitb (<= 0 selects auto, > 256 becomes 256); only the handle
  ! state is reported. The cap is per-machine and never travels in
  ! the blob.
  subroutine itb_pipeline_max_workers(pipe, n, err)
    type(itb_pipeline_t), intent(in) :: pipe
    integer, intent(in)              :: n
    type(itb_error_t), intent(out)   :: err
    call itb_error_set(err, c_itb_triple_max_workers(pipe%handle, int(n, c_int)))
  end subroutine

  ! Rotates the parallax + wrapper masters. The fresh blob is returned
  ! through the optional blob argument (and stays available through
  ! itb_pipeline_save). Must not run concurrently with cipher calls
  ! or open stream sessions on the same Pipeline.
  subroutine itb_pipeline_rekey(pipe, perm_master, wrap_master, err, blob)
    type(itb_pipeline_t), intent(inout)                   :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: perm_master(:)
    integer(c_int8_t), intent(in), target, contiguous     :: wrap_master(:)
    type(itb_error_t), intent(out)                        :: err
    integer(c_int8_t), allocatable, intent(out), optional :: blob(:)
    integer(c_int8_t), allocatable :: rotated(:)
    type(c_ptr) :: pm_p, wm_p

    pm_p = c_null_ptr
    wm_p = c_null_ptr
    if (size(perm_master) > 0) pm_p = c_loc(perm_master(1))
    if (size(wrap_master) > 0) wm_p = c_loc(wrap_master(1))
    call buffer_call(BUF_REKEY, rotated, err, handle=pipe%handle, &
        p1=pm_p, n1=int(size(perm_master), c_size_t), &
        p2=wm_p, n2=int(size(wrap_master), c_size_t))
    if (.not. itb_ok(err)) return
    if (present(blob)) call move_alloc(rotated, blob)
  end subroutine

  ! Zeroes the Pipeline's key material and marks it closed.
  ! Idempotent; subsequent cipher calls return
  ! ITB_STATUS_TRIPLE_CLOSED. The handle stays valid until
  ! itb_pipeline_free.
  subroutine itb_pipeline_close(pipe, err)
    type(itb_pipeline_t), intent(inout) :: pipe
    type(itb_error_t), intent(out)      :: err
    call itb_error_set(err, c_itb_triple_close(pipe%handle))
  end subroutine

  ! Releases the Pipeline handle (libitb closes first, zeroing key
  ! material). Safe to call on an already-freed or never-initialised
  ! record; the status of the underlying Free is deliberately
  ! discarded on this destructor path.
  subroutine itb_pipeline_free(pipe)
    type(itb_pipeline_t), intent(inout) :: pipe
    integer(c_int) :: rc

    if (pipe%handle /= 0_c_intptr_t) then
      rc = c_itb_triple_free(pipe%handle)
      if (rc /= ITB_STATUS_OK) continue
    end if
    pipe%handle = 0_c_intptr_t
  end subroutine

  ! Single Message encrypt: one call, one self-contained wire.
  subroutine itb_encrypt_message(pipe, plain, wire, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: plain(:)
    integer(c_int8_t), allocatable, intent(out)       :: wire(:)
    type(itb_error_t), intent(out)                    :: err
    call cipher(pipe, OP_ENCRYPT_MESSAGE, plain, wire, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_message.
  subroutine itb_decrypt_message(pipe, wire, plain, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: wire(:)
    integer(c_int8_t), allocatable, intent(out)       :: plain(:)
    type(itb_error_t), intent(out)                    :: err
    call cipher(pipe, OP_DECRYPT_MESSAGE, wire, plain, err)
  end subroutine

  ! One-shot stream encrypt for callers holding the whole plaintext
  ! in memory. For bounded-memory streaming use the incremental
  ! sessions / pumps in itb_stream.
  subroutine itb_encrypt_stream_one_shot(pipe, plain, wire, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: plain(:)
    integer(c_int8_t), allocatable, intent(out)       :: wire(:)
    type(itb_error_t), intent(out)                    :: err
    call cipher(pipe, OP_ENCRYPT_STREAM, plain, wire, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_stream_one_shot.
  subroutine itb_decrypt_stream_one_shot(pipe, wire, plain, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer(c_int8_t), intent(in), target, contiguous :: wire(:)
    integer(c_int8_t), allocatable, intent(out)       :: plain(:)
    type(itb_error_t), intent(out)                    :: err
    call cipher(pipe, OP_DECRYPT_STREAM, wire, plain, err)
  end subroutine

  ! Reusable-buffer Single Message encrypt: dst is caller-owned
  ! scratch, grown once to the wire-expansion bound and reused
  ! verbatim across calls; dst(1:n_out) holds the wire on success.
  ! No exact-size trim copy -- the hot path is one FFI call writing
  ! straight into dst via c_loc.
  ! The plain and wire arrays must not overlap; in-place operation
  ! is not supported. Bytes beyond n_out are undefined and may hold
  ! prior-call material; the caller must not read them. After a
  ! failed call the contents of wire are unspecified.
  subroutine itb_encrypt_message_into(pipe, plain, wire, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: plain(:)
    integer(c_int8_t), allocatable, intent(inout), target :: wire(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    call cipher_into(pipe, OP_ENCRYPT_MESSAGE, plain, wire, n_out, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_message_into (same
  ! buffer contract: wire and plain must not overlap; bytes beyond
  ! n_out are undefined). After a failed call -- MAC failure
  ! included -- the contents of plain are unspecified and must not
  ! be interpreted.
  subroutine itb_decrypt_message_into(pipe, wire, plain, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: wire(:)
    integer(c_int8_t), allocatable, intent(inout), target :: plain(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    call cipher_into(pipe, OP_DECRYPT_MESSAGE, wire, plain, n_out, err)
  end subroutine

  ! Reusable-buffer one-shot stream encrypt (see
  ! itb_encrypt_message_into for the buffer contract: plain and
  ! wire must not overlap; bytes beyond n_out are undefined; after
  ! a failed call the contents of wire are unspecified).
  subroutine itb_encrypt_stream_one_shot_into(pipe, plain, wire, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: plain(:)
    integer(c_int8_t), allocatable, intent(inout), target :: wire(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    call cipher_into(pipe, OP_ENCRYPT_STREAM, plain, wire, n_out, err)
  end subroutine

  ! Receive-side counterpart of itb_encrypt_stream_one_shot_into
  ! (same buffer contract: wire and plain must not overlap; bytes
  ! beyond n_out are undefined). After a failed call -- MAC failure
  ! included -- the contents of plain are unspecified and must not
  ! be interpreted.
  subroutine itb_decrypt_stream_one_shot_into(pipe, wire, plain, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer(c_int8_t), intent(in), target, contiguous     :: wire(:)
    integer(c_int8_t), allocatable, intent(inout), target :: plain(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    call cipher_into(pipe, OP_DECRYPT_STREAM, wire, plain, n_out, err)
  end subroutine

  ! ---- profile records -------------------------------------------
  !
  ! A profile record is the JSON object libitb accepts in
  ! itb_register, returns from itb_lookup / itb_inspect, and embeds in
  ! every blob: keys name / mode / width / hash / hashes / keybits /
  ! mac / tagstub / chunk / wrapper / outer / parallax / palette /
  ! segment. Optional keys are omitted when empty / zero. The binding
  ! treats the record as an opaque string; every field rule is
  ! enforced by libitb.

  ! Decodes the profile record embedded in blob without constructing
  ! a Pipeline. No registry read, no primitive probe.
  subroutine itb_inspect(blob, json, err)
    integer(c_int8_t), intent(in), target, contiguous :: blob(:)
    character(:), allocatable, intent(out)            :: json
    type(itb_error_t), intent(out)                    :: err
    integer(c_int8_t), allocatable :: raw(:)
    type(c_ptr) :: blob_p

    blob_p = c_null_ptr
    if (size(blob) > 0) blob_p = c_loc(blob(1))
    call buffer_call(BUF_INSPECT, raw, err, p1=blob_p, &
        n1=int(size(blob), c_size_t))
    if (.not. itb_ok(err)) return
    call bytes_to_string(raw, json)
  end subroutine

  ! Installs a user-defined profile under name from a profile JSON
  ! record (a non-empty "name" key inside the record must equal name);
  ! subsequent Init calls resolve it. Duplicate names return
  ! ITB_STATUS_PROFILE_EXISTS.
  subroutine itb_register(name, profile_json, err)
    character(*), intent(in)       :: name
    character(*), intent(in)       :: profile_json
    type(itb_error_t), intent(out) :: err
    character(kind=c_char), allocatable, target :: c_name(:), c_json(:)

    call itb_to_cstr(name, c_name)
    call itb_to_cstr(profile_json, c_json)
    call itb_error_set(err, &
        c_itb_triple_register(c_loc(c_name(1)), c_loc(c_json(1))))
  end subroutine

  ! The profile registered under name -- a shipped catalogue entry or
  ! a prior itb_register -- as its JSON record. An unregistered name
  ! returns ITB_STATUS_UNKNOWN_PROFILE.
  subroutine itb_lookup(name, json, err)
    character(*), intent(in)               :: name
    character(:), allocatable, intent(out) :: json
    type(itb_error_t), intent(out)         :: err
    character(kind=c_char), allocatable, target :: c_name(:)
    integer(c_int8_t), allocatable :: raw(:)

    call itb_to_cstr(name, c_name)
    call buffer_call(BUF_LOOKUP, raw, err, p1=c_loc(c_name(1)))
    if (.not. itb_ok(err)) return
    call bytes_to_string(raw, json)
  end subroutine

  ! The sorted list of every registered profile name as a JSON array
  ! of strings.
  subroutine itb_profiles(json, err)
    character(:), allocatable, intent(out) :: json
    type(itb_error_t), intent(out)         :: err
    integer(c_int8_t), allocatable :: raw(:)

    call buffer_call(BUF_PROFILES, raw, err)
    if (.not. itb_ok(err)) return
    call bytes_to_string(raw, json)
  end subroutine

  ! Byte-for-byte copy of a libitb JSON output into a Fortran string.
  subroutine bytes_to_string(raw, s)
    integer(c_int8_t), intent(in)          :: raw(:)
    character(:), allocatable, intent(out) :: s
    integer :: i

    allocate (character(len=size(raw)) :: s)
    do i = 1, size(raw)
      s(i:i) = achar(iand(int(raw(i)), 255))
    end do
  end subroutine

  ! The masters pair crosses as (perm, wrap, count): both absent
  ! yields 0, otherwise 2 -- libitb validates the pair.
  subroutine masters_args(perm_master, wrap_master, pm_p, pm_len, wm_p, wm_len, masters)
    integer(c_int8_t), intent(in), target, contiguous, optional :: perm_master(:)
    integer(c_int8_t), intent(in), target, contiguous, optional :: wrap_master(:)
    type(c_ptr), intent(out)       :: pm_p, wm_p
    integer(c_size_t), intent(out) :: pm_len, wm_len, masters

    pm_p = c_null_ptr
    wm_p = c_null_ptr
    pm_len = 0_c_size_t
    wm_len = 0_c_size_t
    masters = 0_c_size_t
    if (present(perm_master)) then
      if (size(perm_master) > 0) pm_p = c_loc(perm_master(1))
      pm_len = int(size(perm_master), c_size_t)
      masters = 2_c_size_t
    end if
    if (present(wrap_master)) then
      if (size(wrap_master) > 0) wm_p = c_loc(wrap_master(1))
      wm_len = int(size(wrap_master), c_size_t)
      masters = 2_c_size_t
    end if
  end subroutine

  ! Single retry-once dispatch site for every variable-size output
  ! buffer (init / save / rekey / inspect / lookup / profiles):
  ! pre-allocate BLOB_CAP, and on ITB_STATUS_BUFFER_TOO_SMALL retry
  ! once with the exact size libitb reported.
  subroutine buffer_call(op, dst, err, handle, p1, n1, p2, n2)
    integer, intent(in)                            :: op
    integer(c_int8_t), allocatable, intent(out)    :: dst(:)
    type(itb_error_t), intent(out)                 :: err
    integer(c_intptr_t), intent(inout), optional   :: handle
    type(c_ptr), intent(in), optional              :: p1, p2
    integer(c_size_t), intent(in), optional        :: n1, n2
    integer(c_int8_t), allocatable, target :: buf(:)
    integer(c_size_t) :: out_len, cap
    integer(c_int)    :: rc

    cap = int(BLOB_CAP, c_size_t)
    allocate (buf(cap))
    out_len = 0_c_size_t
    rc = buffer_dispatch(op, handle, p1, n1, p2, n2, c_loc(buf(1)), cap, out_len)
    if (rc == ITB_STATUS_BUFFER_TOO_SMALL .and. out_len > cap) then
      deallocate (buf)
      cap = out_len
      allocate (buf(cap))
      rc = buffer_dispatch(op, handle, p1, n1, p2, n2, c_loc(buf(1)), cap, out_len)
    end if
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    dst = buf(1_c_size_t:out_len)
  end subroutine

  function buffer_dispatch(op, handle, p1, n1, p2, n2, out_p, out_cap, &
      out_len) result(rc)
    integer, intent(in)                          :: op
    integer(c_intptr_t), intent(inout), optional :: handle
    type(c_ptr), intent(in), optional            :: p1, p2
    integer(c_size_t), intent(in), optional      :: n1, n2
    type(c_ptr), intent(in)                      :: out_p
    integer(c_size_t), intent(in)                :: out_cap
    integer(c_size_t), intent(inout)             :: out_len
    integer(c_int)                               :: rc

    select case (op)
    case (BUF_INIT)
      ! Go closes the undersized attempt; the retry re-runs Init and
      ! yields a fresh session.
      handle = 0_c_intptr_t
      rc = c_itb_triple_init(p1, p2, out_p, out_cap, out_len, handle)
    case (BUF_SAVE)
      rc = c_itb_triple_save(handle, out_p, out_cap, out_len)
    case (BUF_REKEY)
      rc = c_itb_triple_rekey(handle, p1, n1, p2, n2, out_p, out_cap, out_len)
    case (BUF_INSPECT)
      rc = c_itb_triple_inspect(p1, n1, out_p, out_cap, out_len)
    case (BUF_LOOKUP)
      rc = c_itb_triple_lookup(p1, out_p, out_cap, out_len)
    case (BUF_PROFILES)
      rc = c_itb_triple_profiles(out_p, out_cap, out_len)
    case default
      rc = ITB_STATUS_INTERNAL
    end select
  end function

  ! Shared body for the four buffer-in / buffer-out cipher entries:
  ! pre-allocate max(131072, n + n/4 + 131072), retry once on
  ! ITB_STATUS_BUFFER_TOO_SMALL with the exact size the FFI reported.
  subroutine cipher(pipe, op, src, dst, err)
    type(itb_pipeline_t), intent(in)                  :: pipe
    integer, intent(in)                               :: op
    integer(c_int8_t), intent(in), target, contiguous :: src(:)
    integer(c_int8_t), allocatable, intent(out)       :: dst(:)
    type(itb_error_t), intent(out)                    :: err
    integer(c_int8_t), allocatable, target :: buf(:)
    type(c_ptr)         :: src_p, buf_p
    integer(c_size_t)   :: out_len, src_len, cap
    integer(c_int)      :: rc

    src_p = c_null_ptr
    src_len = int(size(src, kind=c_size_t), c_size_t)
    if (src_len > 0) src_p = c_loc(src(1))
    ! Wire-expansion upper bound, computed in c_size_t so payloads
    ! above 2 GiB do not overflow the default 32-bit integer.
    cap = max(131072_c_size_t, src_len + src_len / 4_c_size_t + 131072_c_size_t)
    allocate (buf(cap))
    buf_p = c_loc(buf(1))
    out_len = 0_c_size_t
    rc = dispatch(op, pipe%handle, src_p, src_len, &
        buf_p, cap, out_len)
    ! Guard on len > cap so a stray BUFFER_TOO_SMALL report with
    ! out_len == 0 does not degenerate into allocate(buf(0)) +
    ! c_loc(buf(1)) which is undefined behaviour.
    if (rc == ITB_STATUS_BUFFER_TOO_SMALL .and. out_len > cap) then
      deallocate (buf)
      cap = out_len
      allocate (buf(cap))
      buf_p = c_loc(buf(1))
      rc = dispatch(op, pipe%handle, src_p, src_len, &
          buf_p, cap, out_len)
    end if
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    ! Slice bound stays in c_size_t so payloads above ~1.7 GiB do
    ! not silently narrow through the default 32-bit integer and
    ! return success with an empty dst.
    dst = buf(1_c_size_t:out_len)
  end subroutine

  ! Reusable-buffer body shared by the four *_into cipher entries:
  ! size dst once to max(131072, n + n/4 + 131072), keep it across
  ! calls, retry once on ITB_STATUS_BUFFER_TOO_SMALL with the exact
  ! size the FFI reported. libitb writes straight into dst; the
  ! caller reads dst(1:n_out).
  subroutine cipher_into(pipe, op, src, dst, n_out, err)
    type(itb_pipeline_t), intent(in)                      :: pipe
    integer, intent(in)                                   :: op
    integer(c_int8_t), intent(in), target, contiguous     :: src(:)
    integer(c_int8_t), allocatable, intent(inout), target :: dst(:)
    integer(c_size_t), intent(out)                        :: n_out
    type(itb_error_t), intent(out)                        :: err
    type(c_ptr)       :: src_p
    integer(c_size_t) :: out_len, src_len, cap
    integer(c_int)    :: rc

    n_out = 0_c_size_t
    src_p = c_null_ptr
    src_len = size(src, kind=c_size_t)
    if (src_len > 0) src_p = c_loc(src(1))
    cap = max(131072_c_size_t, src_len + src_len / 4_c_size_t + 131072_c_size_t)
    if (.not. allocated(dst)) then
      allocate (dst(cap))
    else if (size(dst, kind=c_size_t) < cap) then
      deallocate (dst)
      allocate (dst(cap))
    end if
    cap = size(dst, kind=c_size_t)
    out_len = 0_c_size_t
    rc = dispatch(op, pipe%handle, src_p, src_len, c_loc(dst(1)), cap, out_len)
    ! Guard on len > cap so a stray BUFFER_TOO_SMALL report with
    ! out_len == 0 cannot shrink dst to a zero-sized allocation.
    if (rc == ITB_STATUS_BUFFER_TOO_SMALL .and. out_len > cap) then
      deallocate (dst)
      cap = out_len
      allocate (dst(cap))
      out_len = 0_c_size_t
      rc = dispatch(op, pipe%handle, src_p, src_len, c_loc(dst(1)), cap, out_len)
    end if
    call itb_error_set(err, rc)
    if (.not. itb_ok(err)) return
    n_out = out_len
  end subroutine

  function dispatch(op, handle, src_p, src_len, out_p, out_cap, &
      out_len) result(rc)
    integer, intent(in)                :: op
    integer(c_intptr_t), intent(in)    :: handle
    type(c_ptr), intent(in)            :: src_p, out_p
    integer(c_size_t), intent(in)      :: src_len, out_cap
    integer(c_size_t), intent(inout)   :: out_len
    integer(c_int)                     :: rc

    select case (op)
    case (OP_ENCRYPT_MESSAGE)
      rc = c_itb_triple_encrypt_message(handle, src_p, src_len, &
          out_p, out_cap, out_len)
    case (OP_DECRYPT_MESSAGE)
      rc = c_itb_triple_decrypt_message(handle, src_p, src_len, &
          out_p, out_cap, out_len)
    case (OP_ENCRYPT_STREAM)
      rc = c_itb_triple_encrypt_stream(handle, src_p, src_len, &
          out_p, out_cap, out_len)
    case (OP_DECRYPT_STREAM)
      rc = c_itb_triple_decrypt_stream(handle, src_p, src_len, &
          out_p, out_cap, out_len)
    case default
      rc = ITB_STATUS_INTERNAL
    end select
  end function

end module itb_pipeline
