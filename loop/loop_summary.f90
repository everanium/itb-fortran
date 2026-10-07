! The final summary in both renderings, and the two measurements it
! folds in that are not per-worker counters: the process resident set
! and the shared library's pool counters.

module loop_summary
  use, intrinsic :: iso_c_binding
  use itb3
  use loop_size
  use loop_state
  use loop_worker, only: shape_name
  use loop_payload, only: payload_mode_name
  implicit none
  private

  public :: read_rss, pool_snapshot_alloc, pool_snapshot_take, final_summary

  ! Ceiling on the hash-array pool tiers a snapshot is differenced
  ! over; the live count comes from slot 1 of the snapshot itself.
  integer, parameter :: MAX_TIERS = 64

  ! The differenced pool figures of one run.
  type :: pool_delta_t
    integer            :: tiers = 0
    integer(c_int64_t) :: starter(0:MAX_TIERS - 1) = 0_c_int64_t
    integer(c_int64_t) :: get(0:MAX_TIERS - 1) = 0_c_int64_t
    integer(c_int64_t) :: fresh(0:MAX_TIERS - 1) = 0_c_int64_t
    integer(c_int64_t) :: regrow(0:MAX_TIERS - 1) = 0_c_int64_t
    integer(c_int64_t) :: new_bytes(0:MAX_TIERS - 1) = 0_c_int64_t
    integer(c_int64_t) :: buf_get = 0_c_int64_t
    integer(c_int64_t) :: buf_new = 0_c_int64_t
    integer(c_int64_t) :: buf_regrow = 0_c_int64_t
    integer(c_int64_t) :: buf_regrow_bytes = 0_c_int64_t
    integer(c_int64_t) :: chunk_get = 0_c_int64_t
    integer(c_int64_t) :: chunk_new = 0_c_int64_t
    integer(c_int64_t) :: chunk_regrow = 0_c_int64_t
    integer(c_int64_t) :: chunk_regrow_bytes = 0_c_int64_t
  end type

contains

  ! The process's current resident set and its high-water mark in
  ! bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
  ! Both are zero on a platform without that file; the figures are
  ! informational and never enter the verdict.
  subroutine read_rss(current, peak)
    integer(c_int64_t), intent(out) :: current, peak
    integer            :: unit, stat
    character(len=256) :: line

    current = 0_c_int64_t
    peak = 0_c_int64_t
    open (newunit=unit, file="/proc/self/status", status="old", &
          action="read", iostat=stat)
    if (stat /= 0) return
    do
      read (unit, '(a)', iostat=stat) line
      if (stat /= 0) exit
      if (line(1:6) == "VmRSS:") current = status_kb(line)
      if (line(1:6) == "VmHWM:") peak = status_kb(line)
    end do
    close (unit)
  end subroutine

  ! Parses one "Vm...:   1234 kB" line into bytes; zero on any parse
  ! failure.
  function status_kb(line) result(bytes)
    character(*), intent(in) :: line
    integer(c_int64_t)       :: bytes
    integer            :: colon, stat
    integer(c_int64_t) :: kb

    bytes = 0_c_int64_t
    colon = index(line, ":")
    if (colon == 0) return
    read (line(colon + 1:), *, iostat=stat) kb
    if (stat /= 0) return
    bytes = kb * 1024_c_int64_t
  end function

  ! Pool counters. The shared library keeps process-wide monotonic
  ! totals at every pool checkout of its cipher core: per hash-array
  ! tier the starter width, checkouts, constructor misses, regrow
  ! replacements and bytes allocated; for the scratch byte pool and
  ! the parallax chunk pool the checkouts, constructor misses,
  ! regrows and regrow bytes. Two snapshots bracketing the main loop
  ! are differenced into per-run hit / miss figures that tell whether
  ! a pool keeps its items warm between calls or evicts them across
  ! GC cycles. The slot layout is read from the library: slot 1
  ! carries the tier count T, tier i occupies the five slots at
  ! 2 + 5*i, and the two byte pools occupy the eight slots at
  ! 2 + 5*T; the buffer is sized from the binding's length query,
  ! never from a constant.
  function pool_snapshot_alloc(dst) result(ok)
    integer(c_int64_t), allocatable, intent(out) :: dst(:)
    logical                                      :: ok
    integer :: n

    n = itb_pool_stats_len()
    ok = n > 0
    if (.not. ok) then
      allocate (dst(0))
      return
    end if
    allocate (dst(n))
    dst = 0_c_int64_t
  end function

  ! Takes one snapshot into dst. A failure leaves the snapshot zeroed
  ! rather than stopping the run: the counters are informational and
  ! never enter the verdict.
  subroutine pool_snapshot_take(dst)
    integer(c_int64_t), intent(out), target, contiguous :: dst(:)
    type(itb_error_t) :: err
    integer           :: written

    call itb_pool_stats(dst, written, err)
    if (.not. itb_ok(err)) dst = 0_c_int64_t
  end subroutine

  subroutine pool_diff(d)
    type(pool_delta_t), intent(out) :: d
    integer :: i, base, tail, tiers

    if (.not. allocated(pool_warmup) .or. .not. allocated(pool_steady)) return
    if (size(pool_steady) < 9) return
    tiers = int(pool_steady(1))
    if (tiers < 0 .or. tiers > MAX_TIERS) return
    if (1 + 5 * tiers + 8 > size(pool_steady)) return
    d%tiers = tiers
    do i = 0, tiers - 1
      base = 2 + 5 * i
      d%starter(i) = pool_steady(base)
      d%get(i) = pool_steady(base + 1) - pool_warmup(base + 1)
      d%fresh(i) = pool_steady(base + 2) - pool_warmup(base + 2)
      d%regrow(i) = pool_steady(base + 3) - pool_warmup(base + 3)
      d%new_bytes(i) = pool_steady(base + 4) - pool_warmup(base + 4)
    end do
    tail = 2 + 5 * tiers
    d%buf_get = pool_steady(tail) - pool_warmup(tail)
    d%buf_new = pool_steady(tail + 1) - pool_warmup(tail + 1)
    d%buf_regrow = pool_steady(tail + 2) - pool_warmup(tail + 2)
    d%buf_regrow_bytes = pool_steady(tail + 3) - pool_warmup(tail + 3)
    d%chunk_get = pool_steady(tail + 4) - pool_warmup(tail + 4)
    d%chunk_new = pool_steady(tail + 5) - pool_warmup(tail + 5)
    d%chunk_regrow = pool_steady(tail + 6) - pool_warmup(tail + 6)
    d%chunk_regrow_bytes = pool_steady(tail + 7) - pool_warmup(tail + 7)
  end subroutine

  ! Misses over checkouts as a percentage; zero when nothing was
  ! checked out.
  function miss_percent(miss, get) result(x)
    integer(c_int64_t), intent(in) :: miss, get
    real(c_double)                 :: x

    if (get <= 0_c_int64_t) then
      x = 0.0_c_double
      return
    end if
    x = 100.0_c_double * real(miss, c_double) / real(get, c_double)
  end function

  ! Renders s as a JSON string literal with the escapes JSON
  ! requires.
  function json_string(s) result(out)
    character(*), intent(in)  :: s
    character(:), allocatable :: out
    character(len=16), parameter :: HEXDIG = "0123456789abcdef"
    integer :: i, code

    out = '"'
    do i = 1, len(s)
      code = iachar(s(i:i))
      if (s(i:i) == '"') then
        out = out//'\"'
      else if (s(i:i) == '\') then
        out = out//'\\'
      else if (code == 10) then
        out = out//'\n'
      else if (code == 13) then
        out = out//'\r'
      else if (code == 9) then
        out = out//'\t'
      else if (code < 32) then
        out = out//'\u00'// &
              HEXDIG(code / 16 + 1:code / 16 + 1)// &
              HEXDIG(mod(code, 16) + 1:mod(code, 16) + 1)
      else
        out = out//s(i:i)
      end if
    end do
    out = out//'"'
  end function

  ! The effective GC percentage as the runtime reports it: the query
  ! form of the setter (a set-and-restore round trip inside the
  ! library) so the field is the same whether the value came from the
  ! flag, the environment, or the runtime default.
  function effective_gogc() result(n)
    integer :: n

    if (cfg%gogc > 0) then
      n = cfg%gogc
      return
    end if
    n = int(itb_set_gc_percent(-1_c_int))
  end function

  ! Output contract. Both renderings are shared with the Go harness
  ! and every other binding's loop utility field for field: the same
  ! lines in the same order, the same keys in the same order, floats
  ! with a fixed number of decimals so the JSON is byte-identical
  ! across implementations. The Go harness alone adds its
  ! runtime-internal lines after rss: and its runtime-internal keys
  ! after parallax_chunk_pool; nothing here reproduces them because
  ! nothing they read is reachable through the C ABI.
  function final_summary(elapsed_ns) result(code)
    integer(c_int64_t), intent(in) :: elapsed_ns
    integer                        :: code
    integer(c_int64_t) :: total_iters, total_enc, total_dec
    integer(c_int64_t) :: nanos_enc, nanos_dec, avg_enc, avg_dec
    integer(c_int64_t) :: rss_delta
    real(c_double)     :: rss_growth
    integer            :: errors, i, n_emitted
    logical            :: pass
    type(pool_delta_t) :: d
    character(:), allocatable :: text, parts, sp, mp, auto_tier
    type(itb_error_t)         :: tier_err

    total_iters = 0_c_int64_t
    total_enc = 0_c_int64_t
    total_dec = 0_c_int64_t
    nanos_enc = 0_c_int64_t
    nanos_dec = 0_c_int64_t
    errors = 0
    do i = 0, cfg%workers - 1
      total_iters = total_iters + workers(i)%iters
      total_enc = total_enc + workers(i)%bytes_enc
      total_dec = total_dec + workers(i)%bytes_dec
      nanos_enc = nanos_enc + workers(i)%nanos_enc
      nanos_dec = nanos_dec + workers(i)%nanos_dec
      if (workers(i)%failed) errors = errors + 1
    end do

    ! Throughput. Per-direction throughput divides the sum of every
    ! worker's wall time in that direction by the worker count -- the
    ! equivalent single-stream wall time under N-way concurrency --
    ! so each direction reports the aggregate rate it sustained
    ! rather than collapsing to combined/2 (every iteration moves
    ! equal encrypt and decrypt bytes, so a total-elapsed denominator
    ! would give both directions the same figure). The combined rate
    ! keeps total elapsed as the one-glance overall figure.
    avg_enc = 0_c_int64_t
    avg_dec = 0_c_int64_t
    if (nanos_enc > 0_c_int64_t) avg_enc = nanos_enc / int(cfg%workers, c_int64_t)
    if (nanos_dec > 0_c_int64_t) avg_dec = nanos_dec / int(cfg%workers, c_int64_t)

    rss_delta = rss_final - rss_warmup
    rss_growth = 0.0_c_double
    if (rss_warmup > 0_c_int64_t) then
      rss_growth = 100.0_c_double * real(rss_delta, c_double) &
                   / real(rss_warmup, c_double)
    end if

    call pool_diff(d)
    pass = (errors == 0)
    sp = ""
    mp = ""
    if (stream_active) sp = stream_profile
    if (msg_active) mp = msg_profile

    if (cfg%json_output) then
      text = '{"duration_seconds":'// &
             fmt_fixed(real(elapsed_ns, c_double) / 1.0e9_c_double, 3)
      text = text//',"iterations":'//itoa(total_iters)
      text = text//',"per_worker_iterations":['
      do i = 0, cfg%workers - 1
        if (i > 0) text = text//","
        text = text//itoa(workers(i)%iters)
      end do
      text = text//"]"
      text = text//',"bytes_encrypted":'//itoa(total_enc)
      text = text//',"bytes_decrypted":'//itoa(total_dec)
      text = text//',"encrypt_mb_per_sec":'// &
             fmt_fixed(mb_per_sec(total_enc, avg_enc), 1)
      text = text//',"decrypt_mb_per_sec":'// &
             fmt_fixed(mb_per_sec(total_dec, avg_dec), 1)
      text = text//',"combined_mb_per_sec":'// &
             fmt_fixed(mb_per_sec(total_enc + total_dec, elapsed_ns), 1)
      text = text//',"rekeys":'//itoa(rekeys)
      text = text//',"blob_cycles":'//itoa(blob_cycles)
      text = text//',"worker_errors":['
      n_emitted = 0
      do i = 0, cfg%workers - 1
        if (.not. workers(i)%failed) cycle
        if (n_emitted > 0) text = text//","
        n_emitted = n_emitted + 1
        text = text//json_string(workers(i)%error)
      end do
      text = text//"]"
      if (pass) then
        text = text//',"verdict":"PASS"'
      else
        text = text//',"verdict":"FAIL"'
      end if
      text = text//',"shape":"'//shape_name(cfg%shape)//'"'
      text = text//',"stream_profile":'//json_string(sp)
      text = text//',"message_profile":'//json_string(mp)
      text = text//',"hash":'//json_string(cfg%hash)
      text = text//',"mac":'//json_string(cfg%mac)
      text = text//',"payload_bytes":'//itoa(cfg%payload)
      text = text//',"payload_mode":"'//payload_mode_name(cfg%payload_mode)//'"'
      text = text//',"seed":'//u64toa(cfg%seed)
      text = text//',"key_bits":'//itoa(int(cfg%key_bits, c_int64_t))
      text = text//',"nonce_bits":'//itoa(int(cfg%nonce_bits, c_int64_t))
      text = text//',"blob_mode":'//itoa(int(cfg%blob_mode, c_int64_t))
      text = text//',"drbg":'//json_string(cfg%drbg)
      call itb_drbg_auto_tier(auto_tier, tier_err)
      if (.not. itb_ok(tier_err)) auto_tier = ""
      text = text//',"drbg_auto_tier":'//json_string(auto_tier)
      text = text//',"chunk_size_bytes":'//itoa(cfg%chunk_size)
      text = text//',"barrier_fill":'//itoa(int(cfg%barrier_fill, c_int64_t))
      text = text//',"parallax":"'//on_off(cfg%parallax)//'"'
      text = text//',"wrapper":"'//on_off(cfg%wrapper)//'"'
      text = text//',"goroutines_requested":'// &
             itoa(int(cfg%workers_requested, c_int64_t))
      text = text//',"goroutines":'//itoa(int(cfg%workers, c_int64_t))
      text = text//',"concurrency":"'//CONCURRENCY//'"'
      text = text//',"gogc":"'//itoa(int(effective_gogc(), c_int64_t))//'"'
      text = text//',"memlimit_bytes":'//itoa(cfg%memlimit)
      text = text//',"gomaxprocs":'// &
             itoa(int(itb_set_gomaxprocs(0_c_int), c_int64_t))
      text = text//',"microbatch_tiers":'// &
             json_string(policy_label("ITB_MICROBATCH_TIERS"))
      text = text//',"hashpool_starters":'// &
             json_string(policy_label("ITB_HASHPOOL_STARTERS"))
      text = text//',"rss_warmup_bytes":'//itoa(rss_warmup)
      text = text//',"rss_peak_bytes":'//itoa(rss_peak)
      text = text//',"rss_final_bytes":'//itoa(rss_final)
      text = text//',"rss_growth_percent":'//fmt_fixed(rss_growth, 2)
      text = text//',"hash_pool_tiers":['
      n_emitted = 0
      do i = 0, d%tiers - 1
        if (d%starter(i) == 0_c_int64_t) cycle
        if (n_emitted > 0) text = text//","
        n_emitted = n_emitted + 1
        text = text//'{"tier":'//itoa(int(i, c_int64_t))// &
               ',"starter":'//itoa(d%starter(i))// &
               ',"get":'//itoa(d%get(i))// &
               ',"new":'//itoa(d%fresh(i))// &
               ',"regrow":'//itoa(d%regrow(i))// &
               ',"new_bytes":'//itoa(d%new_bytes(i))// &
               ',"miss_percent":'// &
               fmt_fixed(miss_percent(d%fresh(i) + d%regrow(i), d%get(i)), 2)//'}'
      end do
      text = text//"]"
      text = text//',"buf_pool":{"get":'//itoa(d%buf_get)// &
             ',"new":'//itoa(d%buf_new)// &
             ',"regrow":'//itoa(d%buf_regrow)// &
             ',"regrow_bytes":'//itoa(d%buf_regrow_bytes)// &
             ',"miss_percent":'// &
             fmt_fixed(miss_percent(d%buf_regrow, d%buf_get), 2)//'}'
      text = text//',"parallax_chunk_pool":{"get":'//itoa(d%chunk_get)// &
             ',"new":'//itoa(d%chunk_new)// &
             ',"regrow":'//itoa(d%chunk_regrow)// &
             ',"regrow_bytes":'//itoa(d%chunk_regrow_bytes)// &
             ',"miss_percent":'// &
             fmt_fixed(miss_percent(d%chunk_regrow, d%chunk_get), 2)//'}'
      text = text//"}"
      call emit(1_c_int, text)
      code = merge(0, 1, pass)
      return
    end if

    call log_line("=== FINAL ===")
    call log_line("  duration: "// &
                  human_duration((elapsed_ns + 500000_c_int64_t) &
                                 / 1000000_c_int64_t * 1000000_c_int64_t))
    parts = ""
    do i = 0, cfg%workers - 1
      if (i > 0) parts = parts//" + "
      parts = parts//itoa(workers(i)%iters)
    end do
    call log_line("  iterations: "//parts//" = "//itoa(total_iters)//" total")
    call log_line("  throughput: encrypt "//human_rate(total_enc, avg_enc)// &
                  ", decrypt "//human_rate(total_dec, avg_dec)// &
                  ", combined "// &
                  human_rate(total_enc + total_dec, elapsed_ns))
    call log_line("  bytes: "//human_bytes(total_enc)//" encrypted, "// &
                  human_bytes(total_dec)//" decrypted")
    call log_line("  data integrity: "//itoa(total_iters)//"/"// &
                  itoa(total_iters)//" PASS")
    call log_line("  concurrency: "//CONCURRENCY//", workers "// &
                  itoa(int(cfg%workers, c_int64_t))//" (requested "// &
                  itoa(int(cfg%workers_requested, c_int64_t))//")")
    call log_line("  rss: warmup "//human_bytes(rss_warmup)//", peak "// &
                  human_bytes(rss_peak)//", final "// &
                  human_bytes(rss_final)//" (delta "// &
                  human_bytes_signed(rss_delta)//", "// &
                  fmt_fixed(rss_growth, 1)//"% growth)")
    do i = 0, d%tiers - 1
      if (d%starter(i) == 0_c_int64_t) cycle
      call log_line("  hash pool tier "//itoa(int(i, c_int64_t))// &
                    " (starter "//itoa(d%starter(i))//"): get "// &
                    itoa(d%get(i))//", miss "// &
                    itoa(d%fresh(i) + d%regrow(i))//" (new "// &
                    itoa(d%fresh(i))//" + regrow "//itoa(d%regrow(i))// &
                    "), miss "// &
                    fmt_fixed(miss_percent(d%fresh(i) + d%regrow(i), d%get(i)), 2)// &
                    "%, "//human_bytes(d%new_bytes(i))//" allocated")
    end do
    call log_line("  buf pool: get "//itoa(d%buf_get)//", regrow "// &
                  itoa(d%buf_regrow)//" (of which fresh "// &
                  itoa(d%buf_new)//"), miss "// &
                  fmt_fixed(miss_percent(d%buf_regrow, d%buf_get), 2)//"%, "// &
                  human_bytes(d%buf_regrow_bytes)//" regrown")
    call log_line("  parallax chunk pool: get "//itoa(d%chunk_get)// &
                  ", regrow "//itoa(d%chunk_regrow)// &
                  " (of which fresh "//itoa(d%chunk_new)//"), miss "// &
                  fmt_fixed(miss_percent(d%chunk_regrow, d%chunk_get), 2)// &
                  "%, "//human_bytes(d%chunk_regrow_bytes)//" regrown")
    if (rekeys > 0_c_int64_t) call log_line("  rekeys: "//itoa(rekeys))
    if (blob_cycles > 0_c_int64_t) &
      call log_line("  blob cycles: "//itoa(blob_cycles))
    do i = 0, cfg%workers - 1
      if (workers(i)%failed) call log_line("  ERROR: "//workers(i)%error)
    end do
    if (pass) then
      call log_line("  verdict: PASS")
      code = 0
      return
    end if
    call log_line("  verdict: FAIL (errors="// &
                  itoa(int(errors, c_int64_t))//")")
    code = 1
  end function

end module loop_summary
