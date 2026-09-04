! eitb -- command-line demonstrator for the ITB Fortran binding.
!
! Subcommands:
!
!   eitb version                                   library + binding versions
!   eitb profiles                                  registered profile catalogue
!   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
!   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
!
! `encrypt` prints the session blob to stderr as hex; feed that hex
! back to `decrypt` on the receiving side. `profiles` lists the
! registered profile catalogue one name per line; the profiles that
! carry a cipher surface are the ones `encrypt` / `decrypt` accept.

program eitb
  use, intrinsic :: iso_c_binding, only: c_int, c_int8_t, c_int64_t
  use, intrinsic :: iso_fortran_env, only: error_unit
  use itb
  implicit none

  character(:), allocatable :: cmd
  integer(c_int64_t) :: prev_limit
  integer(c_int)     :: prev_gc

  ! Go-runtime pacing caps applied up front so file-scale encrypt /
  ! decrypt runs under a bounded heap; the return values report the
  ! previous settings, not an error.
  prev_limit = itb_set_memory_limit(int(512, c_int64_t) * 1024 * 1024)
  prev_gc = itb_set_gc_percent(20_c_int)

  if (command_argument_count() < 1) call usage()
  cmd = argument(1)

  select case (cmd)
  case ("version")
    call cmd_version()
  case ("profiles")
    call cmd_profiles()
  case ("encrypt")
    if (command_argument_count() /= 4) call usage()
    call cmd_encrypt(argument(2), argument(3), argument(4))
  case ("decrypt")
    if (command_argument_count() /= 5) call usage()
    call cmd_decrypt(argument(2), argument(3), argument(4), argument(5))
  case default
    call usage()
  end select

contains

  subroutine usage()
    write (error_unit, '(a)') "usage: eitb version"
    write (error_unit, '(a)') "       eitb profiles"
    write (error_unit, '(a)') "       eitb encrypt <profile> <in-file> <out-file>"
    write (error_unit, '(a)') "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"
    error stop 2
  end subroutine

  function argument(i) result(arg)
    integer, intent(in)       :: i
    character(:), allocatable :: arg
    integer :: l

    call get_command_argument(i, length=l)
    allocate (character(len=l) :: arg)
    call get_command_argument(i, value=arg)
  end function

  subroutine fail(what, err)
    character(*), intent(in)      :: what
    type(itb_error_t), intent(in) :: err

    write (error_unit, '(a)') "eitb: "//what//": "//itb_error_text(err)
    error stop 1
  end subroutine

  subroutine cmd_version()
    character(:), allocatable :: version
    type(itb_error_t) :: err

    call itb_version(version, err)
    if (.not. itb_ok(err)) call fail("version", err)
    print '(a)', "libitb "//version
    print '(a)', "itb-fortran "//ITB_BINDING_VERSION
  end subroutine

  ! Prints the registered profile catalogue one name per line in the
  ! sorted order itb_profiles returns. The catalogue arrives as a JSON
  ! array of strings; profile names are restricted to [a-z0-9-], so
  ! each quoted run is one complete name and no escape handling is
  ! needed.
  subroutine cmd_profiles()
    character(:), allocatable :: json
    type(itb_error_t) :: err
    integer :: i, start

    call itb_profiles(json, err)
    if (.not. itb_ok(err)) call fail("profiles", err)
    start = 0
    do i = 1, len(json)
      if (json(i:i) == '"') then
        if (start == 0) then
          start = i + 1
        else
          print '(a)', json(start:i - 1)
          start = 0
        end if
      end if
    end do
  end subroutine

  ! Profiles whose canonical name begins with "streaming-" route
  ! through the one-shot streaming buffered pair instead of the
  ! Single Message pair.
  function is_streaming_profile(profile) result(flag)
    character(*), intent(in) :: profile
    logical :: flag
    character(len=10), parameter :: prefix = "streaming-"

    flag = len(profile) >= len(prefix) .and. profile(1:min(len(profile), len(prefix))) == prefix
  end function

  ! Recursively create the parent directory of `path` (mkdir -p).
  ! Fortran has no stdlib mkdir; shell out to `mkdir -p`.
  subroutine ensure_parent_dir(path)
    character(*), intent(in) :: path
    integer :: slash, stat

    slash = index(path, "/", back=.true.)
    if (slash <= 1) return
    call execute_command_line("mkdir -p '"//path(:slash - 1)//"'", &
        wait=.true., exitstat=stat)
    if (stat /= 0) then
      write (error_unit, '(a,i0,a)') &
          "eitb: mkdir -p failed for "//path(:slash - 1)//" (status ", stat, ")"
      error stop 1
    end if
  end subroutine

  subroutine cmd_encrypt(profile, infile, outfile)
    character(*), intent(in) :: profile, infile, outfile
    type(itb_opts_t)     :: opts
    type(itb_pipeline_t) :: pipe
    type(itb_error_t)    :: err
    integer(c_int8_t), allocatable :: plain(:), wire(:), blob(:)

    call read_file(infile, plain)
    call itb_pipeline_init(pipe, profile, opts, err)
    if (.not. itb_ok(err)) call fail("init", err)
    if (is_streaming_profile(profile)) then
      call itb_encrypt_stream_one_shot(pipe, plain, wire, err)
    else
      call itb_encrypt_message(pipe, plain, wire, err)
    end if
    if (.not. itb_ok(err)) call fail("encrypt", err)
    call ensure_parent_dir(outfile)
    call write_file(outfile, wire)
    call itb_pipeline_save(pipe, blob, err)
    if (.not. itb_ok(err)) call fail("save", err)
    write (error_unit, '(a)') hex_encode(blob)
    print '(a,i0,a,i0,a)', "encrypted "//infile//" -> "//outfile// &
        " (", size(plain), " -> ", size(wire), " bytes)"
    call itb_pipeline_free(pipe)
  end subroutine

  subroutine cmd_decrypt(profile, blob_hex, infile, outfile)
    character(*), intent(in) :: profile, blob_hex, infile, outfile
    type(itb_pipeline_t) :: pipe
    type(itb_error_t)    :: err
    integer(c_int8_t), allocatable :: blob(:), wire(:), plain(:)

    call hex_decode(blob_hex, blob)
    call read_file(infile, wire)
    ! The profile shape travels inside the blob; the profile argument
    ! only selects the Single Message or streaming cipher pair.
    call itb_pipeline_load(pipe, blob, err)
    if (.not. itb_ok(err)) call fail("load", err)
    if (is_streaming_profile(profile)) then
      call itb_decrypt_stream_one_shot(pipe, wire, plain, err)
    else
      call itb_decrypt_message(pipe, wire, plain, err)
    end if
    if (.not. itb_ok(err)) call fail("decrypt", err)
    call ensure_parent_dir(outfile)
    call write_file(outfile, plain)
    print '(a,i0,a,i0,a)', "decrypted "//infile//" -> "//outfile// &
        " (", size(wire), " -> ", size(plain), " bytes)"
    call itb_pipeline_free(pipe)
  end subroutine

  subroutine read_file(path, bytes)
    character(*), intent(in)                    :: path
    integer(c_int8_t), allocatable, intent(out) :: bytes(:)
    integer :: unit, stat, n

    open (newunit=unit, file=path, access="stream", form="unformatted", &
        status="old", action="read", iostat=stat)
    if (stat /= 0) then
      write (error_unit, '(a)') "eitb: cannot open "//path
      error stop 1
    end if
    inquire (unit=unit, size=n)
    allocate (bytes(n))
    if (n > 0) read (unit) bytes
    close (unit)
  end subroutine

  subroutine write_file(path, bytes)
    character(*), intent(in)      :: path
    integer(c_int8_t), intent(in) :: bytes(:)
    integer :: unit, stat

    open (newunit=unit, file=path, access="stream", form="unformatted", &
        status="replace", action="write", iostat=stat)
    if (stat /= 0) then
      write (error_unit, '(a)') "eitb: cannot write "//path
      error stop 1
    end if
    if (size(bytes) > 0) write (unit) bytes
    close (unit)
  end subroutine

  function hex_encode(bytes) result(hex)
    integer(c_int8_t), intent(in) :: bytes(:)
    character(:), allocatable     :: hex
    character(len=16), parameter :: digits_lc = "0123456789abcdef"
    integer :: i, v

    allocate (character(len=2 * size(bytes)) :: hex)
    do i = 1, size(bytes)
      v = iand(int(bytes(i)), 255)
      hex(2 * i - 1:2 * i - 1) = digits_lc(v / 16 + 1:v / 16 + 1)
      hex(2 * i:2 * i) = digits_lc(mod(v, 16) + 1:mod(v, 16) + 1)
    end do
  end function

  subroutine hex_decode(hex, bytes)
    character(*), intent(in)                    :: hex
    integer(c_int8_t), allocatable, intent(out) :: bytes(:)
    integer :: i, hi, lo

    if (mod(len(hex), 2) /= 0) then
      write (error_unit, '(a)') "eitb: blob hex has odd length"
      error stop 1
    end if
    allocate (bytes(len(hex) / 2))
    do i = 1, size(bytes)
      hi = nibble(hex(2 * i - 1:2 * i - 1))
      lo = nibble(hex(2 * i:2 * i))
      bytes(i) = int(hi * 16 + lo - merge(256, 0, hi * 16 + lo > 127), c_int8_t)
    end do
  end subroutine

  function nibble(ch) result(v)
    character(len=1), intent(in) :: ch
    integer :: v

    select case (ch)
    case ('0':'9')
      v = iachar(ch) - iachar('0')
    case ('a':'f')
      v = iachar(ch) - iachar('a') + 10
    case ('A':'F')
      v = iachar(ch) - iachar('A') + 10
    case default
      write (error_unit, '(a)') "eitb: invalid hex digit in blob"
      error stop 1
    end select
  end function

end program
