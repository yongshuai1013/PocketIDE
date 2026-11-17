#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_hardware_profile.h"
#include "../app/src/main/cpp/guest_qemud_diagnostics.h"

static void test_source_backed_profile_tokens(void) {
    char value[32];
    assert(guest_qemud_diag_token_value(GUEST_PROFILE_PROC_CMDLINE,
        "qemu", value, sizeof(value)) == 1);
    assert(strcmp(value, "1") == 0);
    assert(guest_qemud_diag_token_value(GUEST_PROFILE_PROC_CMDLINE,
        "android.qemud", value, sizeof(value)) == 1);
    assert(strcmp(value, "ttyS1") == 0);
    assert(guest_qemud_diag_token_value(GUEST_PROFILE_PROC_CMDLINE,
        "androidboot.hardware", value, sizeof(value)) == 1);
    assert(strcmp(value, "goldfish") == 0);
    assert(guest_qemud_diag_token_value("notqemu=1 android.qemud-extra=ttyS1",
        "qemu", value, sizeof(value)) == 0);
    assert(guest_qemud_diag_token_value("qemu=0 android.qemud=ttyS2",
        "android.qemud", value, sizeof(value)) == 1);
    assert(strcmp(value, "ttyS2") == 0);
}

static void test_selected_calls_and_failed_unselected_calls(void) {
    struct guest_qemud_diag_state state;
    struct guest_qemud_diag_record record;
    const uint32_t args[6] = { 5, 0x1000, 16, 0, 0, 0 };
    guest_qemud_diag_state_init(&state);
    assert(guest_qemud_diag_syscall_selected(5));
    assert(guest_qemud_diag_syscall_selected(168));
    assert(guest_qemud_diag_syscall_selected(41));
    assert(guest_qemud_diag_syscall_selected(221));
    assert(!guest_qemud_diag_syscall_selected(192));

    guest_qemud_diag_begin(&state, 5, args, 0x81234000u, 0x81234100u,
        "/proc/cmdline", NULL);
    assert(guest_qemud_diag_finish(&state, 7, &record) == 1);
    assert(record.sequence == 1u && record.syscall_number == 5);
    assert(record.pc == 0x81234000u && record.lr == 0x81234100u && record.result == 7);
    assert(strcmp(record.path, "/proc/cmdline") == 0);

    guest_qemud_diag_begin(&state, 192, args, 0x81234004u, 0x81234104u, NULL, NULL);
    assert(guest_qemud_diag_finish(&state, -ENOMEM, &record) == 1);
    assert(record.sequence == 2u && record.syscall_number == 192);
    assert(record.result == -ENOMEM);

    guest_qemud_diag_begin(&state, 192, args, 0x81234008u, 0x81234108u, NULL, NULL);
    assert(guest_qemud_diag_finish(&state, 0, &record) == 0);
    assert(state.records_emitted == 2u);
}

static void test_cmdline_fd_and_parameter_observation(void) {
    struct guest_qemud_diag_state state;
    guest_qemud_diag_state_init(&state);
    guest_qemud_diag_note_open(&state, "/proc/cmdline", 9);
    assert(state.cmdline_open_count == 1u && state.cmdline_fd == 9);
    assert(strcmp(guest_qemud_diag_fd_path(&state, 9), "/proc/cmdline") == 0);
    const char contents[] = "qemu=1 androidboot.hardware=goldfish android.qemud=ttyS1\n";
    guest_qemud_diag_note_cmdline_read(&state, contents, sizeof(contents) - 1u);
    assert(state.cmdline_read_calls == 1u);
    assert(state.cmdline_read_bytes == sizeof(contents) - 1u);
    assert(state.cmdline_qemu_enabled == 1);
    assert(state.cmdline_qemud_parameter_present == 1);
    assert(strcmp(state.cmdline_qemud_port, "ttyS1") == 0);
    assert(strcmp(guest_qemud_diag_safe_port_label(&state), "ttyS1") == 0);
    assert(guest_qemud_diag_claim_cmdline_observation(&state) == 1);
    assert(guest_qemud_diag_claim_cmdline_observation(&state) == 0);
    guest_qemud_diag_track_fd(&state, 11, "/dev/log/main");
    guest_qemud_diag_dup_fd(&state, 9, 11);
    assert(strcmp(guest_qemud_diag_fd_path(&state, 11), "/proc/cmdline") == 0);
    guest_qemud_diag_untrack_fd(&state, 9);
    assert(guest_qemud_diag_fd_path(&state, 9) == NULL);
    assert(strcmp(guest_qemud_diag_fd_path(&state, 11), "/proc/cmdline") == 0);
    assert(state.cmdline_fd == -1);
    guest_qemud_diag_dup_fd(&state, 40, 11);
    assert(guest_qemud_diag_fd_path(&state, 11) == NULL);

    guest_qemud_diag_state_init(&state);
    const char unusual[] = "android.qemud=ttyS1\001forged";
    guest_qemud_diag_note_cmdline_read(&state, unusual, sizeof(unusual) - 1u);
    assert(strcmp(guest_qemud_diag_safe_port_label(&state),
                  "<noncanonical-redacted>") == 0);
}

static void test_tty_open_and_exit_request_are_observations_only(void) {
    struct guest_qemud_diag_state state;
    assert(guest_qemud_diag_is_tty_s_path("/dev/ttyS1"));
    assert(guest_qemud_diag_is_tty_s_path("/dev/ttyS0"));
    assert(!guest_qemud_diag_is_tty_s_path("/dev/ttySerial"));
    assert(!guest_qemud_diag_is_tty_s_path("/dev/ttyS1-extra"));
    assert(!guest_qemud_diag_is_tty_s_path("/dev/ttyS"));
    guest_qemud_diag_state_init(&state);
    const char selected_cmdline[] = "qemu=1 android.qemud=ttyS1";
    guest_qemud_diag_note_cmdline_read(&state, selected_cmdline,
        sizeof(selected_cmdline) - 1u);
    assert(guest_qemud_diag_is_selected_tty_path(&state, "/dev/ttyS1"));
    guest_qemud_diag_note_open(&state, "/dev/ttyS1", -EOPNOTSUPP);
    assert(state.tty_open_attempts == 1u);
    assert(state.tty_open_result == -EOPNOTSUPP);
    assert(strcmp(state.tty_open_path, "/dev/ttyS1") == 0);
    assert(state.stderr_capture_armed);
    guest_qemud_diag_note_open(&state, "/dev/ttyp1", -EIO);
    guest_qemud_diag_note_open(&state, "/dev/ttySerial", -EIO);
    guest_qemud_diag_note_open(&state, "/dev/ttyS1-extra", -EIO);
    assert(state.tty_open_attempts == 1u);
    assert(strcmp(state.tty_open_path, "/dev/ttyS1") == 0);

    guest_qemud_diag_state_init(&state);
    guest_qemud_diag_note_cmdline_read(&state, selected_cmdline,
        sizeof(selected_cmdline) - 1u);
    guest_qemud_diag_note_open(&state, "/dev/ttyS0", -EIO);
    guest_qemud_diag_note_open(&state, "/dev/ttyS12", -EIO);
    guest_qemud_diag_note_open(&state, "/dev/ttyS1-extra", -EIO);
    assert(!state.stderr_capture_armed);
    assert(!guest_qemud_diag_is_selected_tty_path(&state, "/dev/ttyS0"));
    guest_qemud_diag_state_init(&state);
    const char other_port_cmdline[] = "qemu=1 android.qemud=ttyS2";
    guest_qemud_diag_note_cmdline_read(&state, other_port_cmdline,
        sizeof(other_port_cmdline) - 1u);
    guest_qemud_diag_note_open(&state, "/dev/ttyS2", -EIO);
    assert(!state.stderr_capture_armed);
    assert(!guest_qemud_diag_is_selected_tty_path(&state, "/dev/ttyS2"));

    uint32_t args[6] = { 1, 0, 0, 0, 0, 0 };
    guest_qemud_diag_begin(&state, 248, args, 0x8a60u, 0x8a74u, NULL, NULL);
    assert(state.exit_request_seen == 1);
    assert(state.exit_request_syscall == 248);
    assert(state.exit_request_status == 1u);
    assert(state.exit_request_pc == 0x8a60u);
    assert(state.exit_request_lr == 0x8a74u);

    guest_qemud_diag_state_init(&state);
    uint32_t zero_status_args[6] = {0};
    guest_qemud_diag_begin(&state, 1, zero_status_args,
        0x8b10u, 0x8b24u, NULL, NULL);
    assert(state.exit_request_syscall == 1);
    assert(state.exit_request_status == 0u);
    assert(state.exit_request_pc == 0x8b10u);
    assert(state.exit_request_lr == 0x8b24u);
}

static void test_failure_armed_stderr_preview_is_bounded_and_escaped(void) {
    struct guest_qemud_diag_state state;
    struct guest_qemud_diag_record record;
    size_t amount = 123u;
    uint32_t args[6] = {4, 0, 0, 0, 0, 0};
    guest_qemud_diag_state_init(&state);
    assert(!guest_qemud_diag_claim_stderr_preview(&state, 2, 8, 8, &amount));
    assert(amount == 0u);
    guest_qemud_diag_begin(&state, 5, args, 0x8100u, 0x8110u,
        "/dev/log/main", NULL);
    assert(guest_qemud_diag_finish(&state, -ENOENT, &record) == 1);
    assert(!state.stderr_capture_armed);

    guest_qemud_diag_begin(&state, 250, args, 0x8200u, 0x8210u, NULL, NULL);
    assert(guest_qemud_diag_finish(&state, -ENOSYS, &record) == 1);
    assert(record.lr == 0x8210u && state.stderr_capture_armed);
    assert(!guest_qemud_diag_claim_stderr_preview(&state, 1, 8, 8, &amount));
    assert(!guest_qemud_diag_claim_stderr_preview(&state, 2, 0, 8, &amount));
    assert(!guest_qemud_diag_claim_stderr_preview(&state, 2, -EIO, 8, &amount));

    assert(guest_qemud_diag_claim_stderr_preview(&state, 2, 150, 200, &amount));
    assert(amount == GUEST_QEMUD_DIAG_STDERR_MAX_BYTES);
    assert(guest_qemud_diag_claim_stderr_preview(&state, 2, 20, 50, &amount));
    assert(amount == 20u);
    assert(guest_qemud_diag_claim_stderr_preview(&state, 2, 30, 9, &amount));
    assert(amount == 9u);
    assert(guest_qemud_diag_claim_stderr_preview(&state, 2, 40, 100, &amount));
    assert(amount == 40u);
    assert(!guest_qemud_diag_claim_stderr_preview(&state, 2, 1, 1, &amount));
    assert(state.stderr_preview_chunks == GUEST_QEMUD_DIAG_STDERR_MAX_CHUNKS);
    assert(guest_qemud_diag_guest_range_valid(UINT32_MAX, 1u));
    assert(!guest_qemud_diag_guest_range_valid(UINT32_MAX, 2u));
    assert(guest_qemud_diag_guest_range_valid(0x1000u,
        GUEST_QEMUD_DIAG_STDERR_MAX_BYTES));
    assert(guest_qemud_diag_guest_range_valid(UINT32_MAX, 0u));

    guest_qemud_diag_state_init(&state);
    const char selected_cmdline[] = "qemu=1 android.qemud=ttyS1";
    guest_qemud_diag_note_cmdline_read(&state, selected_cmdline,
        sizeof(selected_cmdline) - 1u);
    guest_qemud_diag_note_open(&state, "/dev/ttyS1", -EOPNOTSUPP);
    assert(state.stderr_capture_armed);
    assert(guest_qemud_diag_claim_stderr_preview(&state, 2, 7, 7, &amount));
    assert(amount == 7u);
    guest_qemud_diag_state_init(&state);
    guest_qemud_diag_note_cmdline_read(&state, selected_cmdline,
        sizeof(selected_cmdline) - 1u);
    guest_qemud_diag_note_open(&state, "/dev/ttyS1-extra", -EOPNOTSUPP);
    assert(!state.stderr_capture_armed);

    const unsigned char raw[] = {'A', 0, '\n', '\r', 0x1b, '"', '\\', 0x7f, 0xff};
    char escaped[GUEST_QEMUD_DIAG_STDERR_ESCAPED_CAP];
    assert(!guest_qemud_diag_escape_bytes(raw, sizeof(raw), escaped, sizeof(escaped)));
    assert(strcmp(escaped, "A\\x00\\x0a\\x0d\\x1b\\\"\\\\\\x7f\\xff") == 0);
    for (size_t i = 0; escaped[i]; ++i)
        assert((unsigned char)escaped[i] >= 0x20u && (unsigned char)escaped[i] <= 0x7eu);
}

static void test_record_budget_is_hard_bounded(void) {
    struct guest_qemud_diag_state state;
    struct guest_qemud_diag_record record;
    const uint32_t args[6] = {0};
    guest_qemud_diag_state_init(&state);
    for (uint32_t i = 0; i < GUEST_QEMUD_DIAG_MAX_RECORDS; ++i) {
        guest_qemud_diag_begin(&state, 3, args, i, i + 1u, NULL, NULL);
        assert(guest_qemud_diag_finish(&state, 0, &record) == 1);
    }
    guest_qemud_diag_begin(&state, 3, args, 0, 1, NULL, NULL);
    assert(guest_qemud_diag_finish(&state, 0, &record) == -1);
    assert(state.records_emitted == GUEST_QEMUD_DIAG_MAX_RECORDS);
    assert(state.records_suppressed == 1u);

    struct guest_qemud_diag_run_budget budget = {0};
    for (uint32_t i = 0; i < GUEST_QEMUD_DIAG_RUN_MAX_LINES; ++i)
        assert(guest_qemud_diag_run_budget_take(&budget) == 1);
    assert(guest_qemud_diag_run_budget_take(&budget) == 0);
    assert(budget.emitted == GUEST_QEMUD_DIAG_RUN_MAX_LINES);
    assert(budget.suppressed == 1u);
}

int main(void) {
    test_source_backed_profile_tokens();
    test_selected_calls_and_failed_unselected_calls();
    test_cmdline_fd_and_parameter_observation();
    test_tty_open_and_exit_request_are_observations_only();
    test_failure_armed_stderr_preview_is_bounded_and_escaped();
    test_record_budget_is_hard_bounded();
    puts("qemud transport profile and bounded syscall/stderr diagnostics: PASS");
    return 0;
}
