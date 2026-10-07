! Size and duration parsing, the monotonic clock, and the human
! renderings of sizes, rates and durations. Every rendering here is
! part of the output contract shared with the Go harness and the
! other bindings' loop utilities, so the formats are fixed to the
! character, not to taste.

module loop_size
  use, intrinsic :: iso_c_binding, only: c_int64_t, c_double
  implicit none
  private

  public :: parse_size, parse_duration, now_ns
  public :: human_bytes, human_bytes_signed, human_rate, human_duration
  public :: mb_per_sec, fmt_fixed, itoa, u64toa, parse_u64

  integer(c_int64_t), parameter :: KIB = 1024_c_int64_t
  integer(c_int64_t), parameter :: MIB = 1048576_c_int64_t
  integer(c_int64_t), parameter :: GIB = 1073741824_c_int64_t

  ! Two's-complement bit pattern of the unsigned ceiling 2**64 - 1
  ! divided by ten: the largest accumulator an unsigned decimal parse
  ! may hold before a further digit overflows.
  integer(c_int64_t), parameter :: U64_DIV10 = 1844674407370955161_c_int64_t
  integer(c_int64_t), parameter :: U64_MOD10 = 5_c_int64_t
  integer(c_int64_t), parameter :: SIGN_BIT = ishft(1_c_int64_t, 63)

contains

  ! Decimal rendering of a signed 64-bit value, no padding.
  function itoa(n) result(s)
    integer(c_int64_t), intent(in) :: n
    character(:), allocatable      :: s
    character(len=24) :: raw

    write (raw, '(i0)') n
    s = trim(raw)
  end function

  ! Fortran has no unsigned integer type, so a uint64 travels as the
  ! signed bit pattern and is rendered here by repeated unsigned
  ! division: ishft(v, -1) is a logical shift, so (v >>> 1) / 5 is
  ! exactly floor(v / 10) over the whole unsigned range.
  function u64toa(v) result(s)
    integer(c_int64_t), intent(in) :: v
    character(:), allocatable      :: s
    integer(c_int64_t) :: rest, q, r
    character(len=24)  :: digits
    integer            :: pos

    if (v >= 0_c_int64_t) then
      s = itoa(v)
      return
    end if
    rest = v
    pos = len(digits)
    digits = " "
    do while (rest /= 0_c_int64_t)
      q = ishft(rest, -1) / U64_MOD10
      r = rest - q * 10_c_int64_t
      digits(pos:pos) = achar(iachar('0') + int(r))
      pos = pos - 1
      rest = q
    end do
    s = digits(pos + 1:)
  end function

  ! Unsigned-less-than over two's-complement bit patterns: flipping
  ! the sign bit of both operands turns the unsigned order into the
  ! signed one.
  pure function ult(a, b) result(lt)
    integer(c_int64_t), intent(in) :: a, b
    logical :: lt
    lt = ieor(a, SIGN_BIT) < ieor(b, SIGN_BIT)
  end function

  ! Parses an unsigned decimal integer into its 64-bit bit pattern.
  ! Rejects an empty string, a non-digit, and a value above
  ! 2**64 - 1.
  function parse_u64(s, out) result(ok)
    character(*), intent(in)        :: s
    integer(c_int64_t), intent(out) :: out
    logical                         :: ok
    integer            :: i, d
    integer(c_int64_t) :: acc

    out = 0_c_int64_t
    ok = .false.
    if (len_trim(s) == 0) return
    acc = 0_c_int64_t
    do i = 1, len(s)
      if (s(i:i) < '0' .or. s(i:i) > '9') return
      d = iachar(s(i:i)) - iachar('0')
      if (ult(U64_DIV10, acc)) return
      if (acc == U64_DIV10 .and. d > 5) return
      acc = acc * 10_c_int64_t + int(d, c_int64_t)
    end do
    out = acc
    ok = .true.
  end function

  ! Fixed-point rendering with d decimals and no exponent. The
  ! gfortran f0.d edit descriptor drops the integer zero of a
  ! magnitude below one (".50", "-.50"), which is neither the C
  ! reference's rendering nor valid JSON, so the zero is restored
  ! here.
  function fmt_fixed(x, d) result(s)
    real(c_double), intent(in) :: x
    integer, intent(in)        :: d
    character(:), allocatable  :: s
    character(len=64) :: raw
    character(len=16) :: edit

    write (edit, '("(f0.",i0,")")') d
    write (raw, edit) x
    s = trim(adjustl(raw))
    if (len(s) >= 1) then
      if (s(1:1) == '.') then
        s = '0'//s
      else if (len(s) >= 2) then
        if (s(1:2) == '-.') s = '-0'//s(2:)
      end if
    end if
  end function

  ! Parses a human byte-size string ("16MB", "1MiB", "512K",
  ! "1073741824") into a byte count. Every suffix is a binary
  ! multiple: K/KB/KiB = 1024, M/MB/MiB = 1024**2, G/GB/GiB =
  ! 1024**3, B or none = bytes; matching is case-insensitive and
  ! surrounding whitespace is trimmed.
  function parse_size(s, out) result(ok)
    character(*), intent(in)        :: s
    integer(c_int64_t), intent(out) :: out
    logical                         :: ok
    character(:), allocatable :: body, up
    integer(c_int64_t) :: mult, n
    integer :: digits, i

    out = 0_c_int64_t
    ok = .false.
    body = trim(adjustl(s))
    if (len(body) == 0) return
    up = upcase(body)
    mult = 1_c_int64_t
    digits = len(up)
    if (ends_with(up, "KIB")) then
      mult = KIB
      digits = len(up) - 3
    else if (ends_with(up, "MIB")) then
      mult = MIB
      digits = len(up) - 3
    else if (ends_with(up, "GIB")) then
      mult = GIB
      digits = len(up) - 3
    else if (ends_with(up, "KB")) then
      mult = KIB
      digits = len(up) - 2
    else if (ends_with(up, "MB")) then
      mult = MIB
      digits = len(up) - 2
    else if (ends_with(up, "GB")) then
      mult = GIB
      digits = len(up) - 2
    else if (ends_with(up, "K")) then
      mult = KIB
      digits = len(up) - 1
    else if (ends_with(up, "M")) then
      mult = MIB
      digits = len(up) - 1
    else if (ends_with(up, "G")) then
      mult = GIB
      digits = len(up) - 1
    else if (ends_with(up, "B")) then
      mult = 1_c_int64_t
      digits = len(up) - 1
    end if
    do while (digits > 0)
      if (up(digits:digits) /= ' ') exit
      digits = digits - 1
    end do
    if (digits == 0) return
    do i = 1, digits
      if (up(i:i) < '0' .or. up(i:i) > '9') return
    end do
    if (.not. parse_u64(up(1:digits), n)) return
    if (n < 0_c_int64_t) return
    if (mult > 1_c_int64_t) then
      if (n > huge(n) / mult) return
    end if
    out = n * mult
    ok = .true.
  end function

  ! Parses the Go duration grammar -- a sequence of decimal numbers
  ! each followed by a unit (h, m, s, ms, us, ns), such as "30s",
  ! "5m", "1h30m", "3s500ms", "1.5s" -- into nanoseconds.
  function parse_duration(s, out_ns) result(ok)
    character(*), intent(in)        :: s
    integer(c_int64_t), intent(out) :: out_ns
    logical                         :: ok
    character(:), allocatable :: body
    real(c_double) :: total, v, mult
    integer :: pos, start, stat
    logical :: matched

    out_ns = 0_c_int64_t
    ok = .false.
    body = trim(adjustl(s))
    if (len(body) == 0) return
    total = 0.0_c_double
    pos = 1
    do while (pos <= len(body))
      if (.not. (is_digit(body(pos:pos)) .or. body(pos:pos) == '.')) return
      start = pos
      do while (pos <= len(body))
        if (.not. (is_digit(body(pos:pos)) .or. body(pos:pos) == '.')) exit
        pos = pos + 1
      end do
      read (body(start:pos - 1), *, iostat=stat) v
      if (stat /= 0) return
      if (v < 0.0_c_double) return
      mult = 0.0_c_double
      matched = .true.
      if (unit_at(body, pos, "ns")) then
        mult = 1.0_c_double
        pos = pos + 2
      else if (unit_at(body, pos, "us")) then
        mult = 1.0e3_c_double
        pos = pos + 2
      else if (unit_at(body, pos, "ms")) then
        mult = 1.0e6_c_double
        pos = pos + 2
      else if (unit_at(body, pos, "s")) then
        mult = 1.0e9_c_double
        pos = pos + 1
      else if (unit_at(body, pos, "m")) then
        mult = 60.0e9_c_double
        pos = pos + 1
      else if (unit_at(body, pos, "h")) then
        mult = 3600.0e9_c_double
        pos = pos + 1
      else
        matched = .false.
      end if
      if (.not. matched) return
      total = total + v * mult
    end do
    if (total > 9.2e18_c_double) return
    out_ns = int(total, c_int64_t)
    ok = .true.
  end function

  ! Monotonic wall clock in nanoseconds. gfortran's system_clock with
  ! 64-bit arguments reports a 1 ns rate off the POSIX monotonic
  ! clock; a coarser rate is scaled rather than trusted.
  function now_ns() result(ns)
    integer(c_int64_t) :: ns
    integer(c_int64_t) :: cnt, rate

    call system_clock(count=cnt, count_rate=rate)
    if (rate <= 0_c_int64_t) then
      ns = 0_c_int64_t
    else if (rate == 1000000000_c_int64_t) then
      ns = cnt
    else
      ns = (cnt / rate) * 1000000000_c_int64_t &
           + mod(cnt, rate) * (1000000000_c_int64_t / rate)
    end if
  end function

  ! Renders a byte count with a binary-unit suffix: "1.0GiB",
  ! "16.0MiB", "4.0KiB", "512B".
  function human_bytes(n) result(s)
    integer(c_int64_t), intent(in) :: n
    character(:), allocatable      :: s

    if (n >= GIB) then
      s = fmt_fixed(real(n, c_double) / real(GIB, c_double), 1)//"GiB"
    else if (n >= MIB) then
      s = fmt_fixed(real(n, c_double) / real(MIB, c_double), 1)//"MiB"
    else if (n >= KIB) then
      s = fmt_fixed(real(n, c_double) / real(KIB, c_double), 1)//"KiB"
    else
      s = itoa(n)//"B"
    end if
  end function

  ! Renders a possibly-negative byte delta with an explicit sign.
  function human_bytes_signed(n) result(s)
    integer(c_int64_t), intent(in) :: n
    character(:), allocatable      :: s

    if (n < 0_c_int64_t) then
      s = "-"//human_bytes(-n)
    else
      s = "+"//human_bytes(n)
    end if
  end function

  ! Binary MiB per second over a nanosecond window; zero when the
  ! window is unmeasured.
  function mb_per_sec(bytes, ns) result(x)
    integer(c_int64_t), intent(in) :: bytes, ns
    real(c_double)                 :: x

    if (ns <= 0_c_int64_t) then
      x = 0.0_c_double
      return
    end if
    x = real(bytes, c_double) / real(MIB, c_double) &
        / (real(ns, c_double) / 1.0e9_c_double)
  end function

  ! Renders a throughput as "123.4MB/s" (binary MiB per second) or
  ! "n/a" for an unmeasured window.
  function human_rate(bytes, ns) result(s)
    integer(c_int64_t), intent(in) :: bytes, ns
    character(:), allocatable      :: s

    if (ns <= 0_c_int64_t) then
      s = "n/a"
      return
    end if
    s = fmt_fixed(mb_per_sec(bytes, ns), 1)//"MB/s"
  end function

  ! Renders a duration the way Go's time.Duration prints: below one
  ! second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
  ! where the hour part appears when non-zero, the minute part when
  ! the hour part appears or the minutes are non-zero, and the
  ! seconds carry their fraction with trailing zeros removed ("5s",
  ! "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
  function human_duration(ns) result(s)
    integer(c_int64_t), intent(in) :: ns
    character(:), allocatable      :: s
    integer(c_int64_t) :: v, hours, rem, minutes, seconds, frac, ms

    v = ns
    if (v < 0_c_int64_t) v = -v
    if (v == 0_c_int64_t) then
      s = "0s"
      return
    end if
    if (v < 1000000000_c_int64_t) then
      ms = v / 1000000_c_int64_t
      frac = mod(v, 1000000_c_int64_t) * 1000_c_int64_t
      s = itoa(ms)//fraction_of(frac)//"ms"
      return
    end if
    hours = v / 3600000000000_c_int64_t
    rem = mod(v, 3600000000000_c_int64_t)
    minutes = rem / 60000000000_c_int64_t
    rem = mod(rem, 60000000000_c_int64_t)
    seconds = rem / 1000000000_c_int64_t
    frac = mod(rem, 1000000000_c_int64_t)
    s = ""
    if (hours > 0_c_int64_t) s = itoa(hours)//"h"
    if (hours > 0_c_int64_t .or. minutes > 0_c_int64_t) s = s//itoa(minutes)//"m"
    s = s//itoa(seconds)//fraction_of(frac)//"s"
  end function

  ! The fractional part of a nanosecond remainder (0 .. 1e9) as
  ! ".ddd" with trailing zeros removed; the empty string for zero.
  function fraction_of(frac_ns) result(s)
    integer(c_int64_t), intent(in) :: frac_ns
    character(:), allocatable      :: s
    character(len=9) :: digits
    integer :: n

    if (frac_ns == 0_c_int64_t) then
      s = ""
      return
    end if
    write (digits, '(i9.9)') frac_ns
    n = 9
    do while (n > 0)
      if (digits(n:n) /= '0') exit
      n = n - 1
    end do
    s = "."//digits(1:n)
  end function

  pure function is_digit(c) result(d)
    character(len=1), intent(in) :: c
    logical :: d
    d = (c >= '0' .and. c <= '9')
  end function

  ! Whether the unit token sits at pos and is not the prefix of a
  ! longer alphabetic run ("m" must not match the "m" of "ms").
  pure function unit_at(s, pos, unit) result(hit)
    character(*), intent(in) :: s
    integer, intent(in)      :: pos
    character(*), intent(in) :: unit
    logical :: hit
    integer :: last

    hit = .false.
    last = pos + len(unit) - 1
    if (last > len(s)) return
    if (s(pos:last) /= unit) return
    if (last < len(s)) then
      if (is_alpha(s(last + 1:last + 1))) return
    end if
    hit = .true.
  end function

  pure function is_alpha(c) result(a)
    character(len=1), intent(in) :: c
    logical :: a
    a = (c >= 'a' .and. c <= 'z') .or. (c >= 'A' .and. c <= 'Z')
  end function

  pure function ends_with(s, suffix) result(hit)
    character(*), intent(in) :: s, suffix
    logical :: hit

    hit = .false.
    if (len(suffix) > len(s)) return
    hit = (s(len(s) - len(suffix) + 1:) == suffix)
  end function

  pure function upcase(s) result(up)
    character(*), intent(in)  :: s
    character(len=len(s))     :: up
    integer :: i

    do i = 1, len(s)
      if (s(i:i) >= 'a' .and. s(i:i) <= 'z') then
        up(i:i) = achar(iachar(s(i:i)) - 32)
      else
        up(i:i) = s(i:i)
      end if
    end do
  end function

end module loop_size
