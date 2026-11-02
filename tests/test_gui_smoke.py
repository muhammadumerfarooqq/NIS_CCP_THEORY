"""Smoke tests for the GUI. The window is built but kept hidden (withdrawn).

If this computer has no display, Tk cannot start; then these tests are
SKIPPED, not failed. The pure helper functions in gui.py are tested in
tests/test_gui_helpers.py, which needs no display."""

import os
import tempfile
import unittest

try:
    import tkinter as tk
except ImportError as error:        # some Python installs have no tkinter
    raise unittest.SkipTest(f"tkinter is not installed: {error}")

import attack
import benchmark
import cipher
import gui

PLAIN = "DEFENDTHEEASTWALLOFTHECASTLE"
KEY = "CRYPTOGRAPHY"
STAGE1 = "FVDTGRZYETHQVNYAECLKHTJYUKJT"
FINAL = "FEEUVYTACYKDZHYLJJTRQNKTTGVH"


def all_widgets(widget):
    """Every widget below `widget`, at any depth."""
    for child in widget.winfo_children():
        yield child
        yield from all_widgets(child)


class GuiTestCase(unittest.TestCase):
    """Builds one hidden window for each test class."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest(f"no display available for Tk: {error}")
        cls.root.withdraw()
        cls.app = gui.App(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.app.wait_until_idle(timeout=30)
        cls.app.close()                              # also destroys the window

    def setUp(self):
        # Start every test from a clean screen.
        self.app.wait_until_idle(timeout=30)
        self.app.notebook.select(gui.TAB_LOCK)
        self.app.clear_all()
        self.app.key_var.set("")
        self.app.rails_var.set("4")
        self.app.inline_var.set("")
        self.app._status_memory = {tab: (m, "info") for tab, m in gui.READY_MESSAGES.items()}

    def fill(self, message, key, rails):
        self.app.set_message(message)
        self.app.key_var.set(key)
        self.app.rails_var.set(str(rails))


class TestLockUnlock(GuiTestCase):
    def test_lock_gives_the_real_cipher_output(self):
        self.fill(PLAIN, KEY, 5)
        returned = self.app.do_encrypt()
        out = self.app.get_outputs()
        self.assertEqual(out["cleaned"], PLAIN)
        self.assertEqual(out["middle"], STAGE1)                      # after Stage 1 - Vigenere
        self.assertEqual(out["final"], FINAL)                        # after Stage 2 - Rail Fence
        self.assertEqual((out["middle"], out["final"]), cipher.custom_encrypt(PLAIN, KEY, 5))
        self.assertEqual(returned, FINAL)
        self.assertEqual(self.app.inline_text(), "")
        self.assertIn("yes", self.app.check_label.cget("text"))      # "Unlocks back to the original: yes"
        self.assertEqual(str(self.app.check_label.cget("fg")), gui.GREEN)
        self.assertTrue(self.app.time_label.cget("text").startswith("Done in "))

    def test_unlock_returns_the_original(self):
        self.fill(FINAL, KEY, 5)
        returned = self.app.do_decrypt()
        out = self.app.get_outputs()
        self.assertEqual(returned, PLAIN)
        self.assertEqual(out["final"], PLAIN)                        # after undoing Stage 1
        self.assertEqual(out["middle"], STAGE1)                      # after undoing Stage 2 only
        self.assertIn("yes", self.app.check_label.cget("text"))

    def test_removed_characters_are_reported(self):
        self.fill("Hello, World 123", KEY, 3)
        self.app.do_encrypt()
        self.assertEqual(self.app.get_outputs()["cleaned"], "HELLOWORLD")
        self.assertIn("6 characters were removed because only A-Z is supported", self.app.status_var.get())
        self.assertEqual(self.app._out[0]["note"].cget("text"), "6 characters removed")

    def test_nine_letter_key_shows_red_inline_message_and_no_output(self):
        self.fill(PLAIN, "ABCDEFGHI", 5)                             # 9 letters
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("too short", self.app.inline_text())
        self.assertEqual(str(self.app.inline_label.cget("fg")), gui.RED)
        self.assertEqual(self.app.get_outputs(), {"cleaned": "", "middle": "", "final": ""})
        self.assertEqual(self.app.status_label.cget("fg"), gui.RED)
        self.assertIsNone(self.app.do_decrypt())                     # unlock refuses it too

    def test_other_bad_inputs_show_inline_messages(self):
        self.fill("", KEY, 5)
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("message", self.app.inline_text())
        self.fill("1234 !!!", KEY, 5)
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("no letters", self.app.inline_text())
        self.fill(PLAIN, KEY, 11)
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("between 2 and 10", self.app.inline_text())
        self.fill(PLAIN, KEY, "abc")
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("whole number", self.app.inline_text())
        self.fill(PLAIN, "ABCDEFGHIJ1", 5)
        self.assertIsNone(self.app.do_encrypt())
        self.assertIn("letters only", self.app.inline_text())

    def test_live_key_counter(self):
        self.app.key_var.set("ABCDEFG")
        self.assertEqual(self.app.counter_label.cget("text"), "7 / 10 letters")
        self.assertEqual(str(self.app.counter_label.cget("fg")), gui.RED)
        self.app.key_var.set("ABCDEFGHIJ")
        self.assertEqual(self.app.counter_label.cget("text"), "10 / 10 letters")
        self.assertEqual(str(self.app.counter_label.cget("fg")), gui.GREEN)

    def test_key_field_only_accepts_letters(self):
        self.assertTrue(self.app._key_edit_allowed("Abc"))
        self.assertTrue(self.app._key_edit_allowed(""))
        self.assertFalse(self.app._key_edit_allowed("abc1"))
        self.assertFalse(self.app._key_edit_allowed("ab c"))
        self.assertIn("Only the letters A-Z", self.app.inline_text())

    def test_stage_colours(self):
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        self.assertEqual(str(self.app._out[1]["text"].cget("bg")), gui.STAGE1_BG)    # Stage 1 = blue
        self.assertEqual(str(self.app._out[2]["text"].cget("bg")), gui.STAGE2_BG)    # Stage 2 = orange
        self.assertIn("Stage 1 - Vigenere", self.app._out[1]["caption"].cget("text"))
        self.assertIn("Stage 2 Rail Fence", self.app._out[2]["caption"].cget("text"))
        self.fill(FINAL, KEY, 5)
        self.app.do_decrypt()
        self.assertEqual(str(self.app._out[1]["text"].cget("bg")), gui.STAGE2_BG)    # undo Stage 2 = orange
        self.assertEqual(str(self.app._out[2]["text"].cget("bg")), gui.STAGE1_BG)    # undo Stage 1 = blue
        self.assertIn("undoing Stage 2", self.app._out[1]["caption"].cget("text"))
        self.assertIn("undoing Stage 1", self.app._out[2]["caption"].cget("text"))

    def test_load_sample_and_clear(self):
        self.app.load_sample()
        self.assertEqual(self.app.get_message(), gui.SAMPLE_MESSAGE)
        self.assertEqual(self.app.key_var.get(), gui.SAMPLE_KEY)
        self.assertTrue(self.app.do_encrypt())
        self.app.clear_all()
        self.assertEqual(self.app.get_message(), "")
        self.assertEqual(self.app.get_outputs()["final"], "")

    def test_enter_key_in_the_key_field_locks(self):
        # A hidden window has no keyboard focus, so a generated key press would
        # never arrive. Instead check that Return IS bound to the handler, then
        # call that handler (exactly what Tk does when Enter is pressed).
        self.assertTrue(self.app.key_entry.bind("<Return>"))
        self.fill(PLAIN, KEY, 5)
        self.app._on_key_enter()
        self.assertEqual(self.app.get_outputs()["final"], FINAL)

    def test_show_working_window(self):
        self.assertIsNone(self.app.show_working())                   # nothing locked yet
        self.assertIn("Lock", self.app.inline_text())
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        win = self.app.show_working()
        try:
            self.root.update()
            self.assertEqual(win.title(), "Show working")
        finally:
            win.destroy()


class TestLockUnlockRoundTrip(GuiTestCase):
    def test_lock_then_unlock_the_ciphertext_gives_the_original(self):
        # (There is no "Move output to input" button any more: the ciphertext is pasted into the message box.)
        self.fill("Meet me at the old stone bridge at dawn.", "LEMONSQUEEZE", 6)
        locked = self.app.do_encrypt()
        self.app.set_message(locked)
        self.assertEqual(self.app.do_decrypt(), "MEETMEATTHEOLDSTONEBRIDGEATDAWN")

    def test_the_output_is_not_kept_after_clear(self):
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        self.app.clear_all()
        self.assertEqual(self.app.get_outputs(), {"cleaned": "", "middle": "", "final": ""})
        self.assertIsNone(self.app._last_op)                         # Show Working has nothing left either


class TestWorkingDocument(GuiTestCase):
    """The text of the Show Working window (pure function, but kept with the GUI tests)."""

    def test_lock_working_has_both_stages_and_matches(self):
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        segments, matches, error = gui.build_working_document(self.app._last_op)
        text = "\n".join(t for _, t in segments)
        self.assertTrue(matches)
        self.assertEqual(error, "")
        self.assertIn("All rows match cipher.py: yes", text)
        self.assertIn("D (3) + C (2) = 5  ->  F", text)
        self.assertIn("(letter + key letter) mod 26", text)
        self.assertLess(text.index("STAGE 1 - VIGENERE"), text.index("STAGE 2 - RAIL FENCE"))
        self.assertIn(STAGE1, text)                                  # the Rail Fence input line shows Stage 1 text

    def test_unlock_working_goes_backwards(self):
        self.fill(FINAL, KEY, 5)
        self.app.do_decrypt()
        segments, matches, _ = gui.build_working_document(self.app._last_op)
        text = "\n".join(t for _, t in segments)
        self.assertTrue(matches)
        self.assertLess(text.index("UNDO STAGE 2"), text.index("UNDO STAGE 1"))
        self.assertIn("All rows match cipher.py: yes", text)
        self.assertIn("(letter - key letter) mod 26", text)

    def test_working_reports_a_mismatch_instead_of_hiding_it(self):
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        broken = dict(self.app._last_op, middle="Z" * len(STAGE1))   # not what cipher.py gives
        _, matches, error = gui.build_working_document(broken)
        self.assertFalse(matches)
        self.assertNotEqual(error, "")


class TestAttackTab(GuiTestCase):
    def setUp(self):
        super().setUp()
        # Every test starts from the tab's default settings, so one test cannot leak its choices into the next.
        self.app.attack_var.set("freq")
        self.app.n_var.set("500")
        self.app.crib_size_var.set("30")
        self.app.attack_inline_var.set("")
        self.app._clear_attack_result()

    def test_frequency_attack_on_a_test_message(self):
        self.app.n_var.set("2500")
        self.assertTrue(self.app.run_attack())
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(self.app.attack_inline_var.get(), "")
        self.assertEqual(self.app.result_vars["guesses"].get(), "144")
        self.assertTrue(self.app.result_vars["time"].get().endswith("ms"))
        self.assertIn("Correct: yes", self.app.correct_var.get())    # 2500 letters: reliably broken
        self.assertEqual(self.app.truth_var.get(), "")               # truth stays hidden ...
        self.assertTrue(self.app.reveal_truth())                     # ... until asked for
        self.assertIn("True key:", self.app.truth_var.get())
        recovered = self.app._get_text(self.app.recovered_text)
        self.assertEqual(len(recovered), 300)
        self.assertTrue(self.app._truth["plaintext"].startswith(recovered))

    def test_known_plaintext_attack_on_a_test_message(self):
        self.app.attack_var.set("kpa")
        self.app.crib_size_var.set("30")
        self.app.run_attack()
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertIn("Correct: yes", self.app.correct_var.get())
        self.assertEqual(self.app.result_vars["rails"].get(), str(self.app._truth["rails"]))
        self.assertEqual(self.app.result_vars["key"].get(), self.app._truth["key"])

    def test_a_50_letter_test_message_can_be_attacked(self):
        self.assertEqual(list(self.app.n_combo.cget("values")), [str(n) for n in attack.TEXT_LENGTHS])
        self.assertIn("50", self.app.n_combo.cget("values"))
        self.app.n_var.set("50")
        self.assertTrue(self.app.run_attack())
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(self.app.attack_inline_var.get(), "")
        self.assertTrue(self.app.result_vars["time"].get().endswith("ms"))

    def test_the_crib_size_is_only_available_for_the_known_plaintext_attack(self):
        self.app.attack_var.set("freq")
        self.assertEqual(str(self.app.crib_spin.cget("state")), "disabled")
        self.app.attack_var.set("kpa")
        self.assertEqual(str(self.app.crib_spin.cget("state")), "normal")

    def test_bad_crib_size_is_rejected_inline_for_the_known_plaintext_attack(self):
        self.app.attack_var.set("kpa")
        self.app.crib_size_var.set("5")
        self.assertFalse(self.app.run_attack())
        self.assertIn("between 10 and 40", self.app.attack_inline_var.get())
        self.app.crib_size_var.set("abc")
        self.assertFalse(self.app.run_attack())
        self.assertIn("whole numbers", self.app.attack_inline_var.get())

    def test_the_crib_size_is_ignored_by_the_frequency_attack(self):
        self.app.crib_size_var.set("5")                              # would be rejected for the other attack
        self.assertTrue(self.app.run_attack())
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(self.app.attack_inline_var.get(), "")

    def test_the_window_stays_responsive_while_the_attack_runs(self):
        self.app.n_var.set("5000")
        self.assertTrue(self.app.run_attack())
        self.assertTrue(self.app.is_busy())
        self.assertFalse(self.app.run_attack())                      # a second press is ignored while busy
        self.assertEqual(str(self.app.attack_button.cget("state")), "disabled")
        self.root.update()                                           # the window can still handle events
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(str(self.app.attack_button.cget("state")), "normal")


class TestSavedAttackTable(GuiTestCase):
    def test_the_table_shows_the_real_columns_of_the_csv(self):
        data = self.app.load_saved_attack_results()
        self.assertIsNotNone(data)
        summary = gui.attack_summary(gui.read_attack_csv())
        rows = [list(self.app.attack_table.item(i)["values"]) for i in self.app.attack_table.get_children()]
        self.assertEqual(len(rows), len(attack.TEXT_LENGTHS))
        for shown, expected in zip(rows, summary["rows"]):
            self.assertEqual([str(v) for v in shown], expected)
        headings = [self.app.attack_table.heading(c)["text"] for c in self.app.attack_table["columns"]]
        self.assertEqual(headings[0], "Length N")
        self.assertIn("Frequency", headings[1])
        self.assertIn("time", headings[2])
        self.assertIn(f"crib {summary['crib']}", headings[3])
        self.assertEqual(len(headings), 5)
        self.assertIn(f"{summary['trials']} trials per row", self.app.attack_table_frame.cget("text"))

    def test_opening_the_tab_loads_the_table(self):
        self.app.attack_table.delete(*self.app.attack_table.get_children())
        self.app.notebook.select(gui.TAB_ATTACK)
        self.app._on_tab_changed()
        self.assertEqual(len(self.app.attack_table.get_children()), len(attack.TEXT_LENGTHS))

    def test_a_missing_csv_shows_the_friendly_line_and_does_not_crash(self):
        self.app.load_saved_attack_results()                         # something on screen first
        missing = os.path.join(tempfile.gettempdir(), "nope_attack_phase7.csv")
        self.assertIsNone(self.app.load_saved_attack_results(path=missing))
        self.assertEqual(self.app.attack_note_var.get(), "Run python attack.py to create results/attack_results.csv")
        self.assertEqual(str(self.app.attack_note_label.cget("fg")), gui.RED)
        self.assertEqual(self.app.attack_table.get_children(), ())   # the old rows are gone, not left stale

    def test_a_damaged_csv_shows_a_message_and_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.csv")
            with open(bad, "w", newline="") as fh:
                fh.write("table,x\ntable1,1\n")
            self.assertIsNone(self.app.load_saved_attack_results(path=bad))
        self.assertIn("not in the expected format", self.app.attack_note_var.get())

    def test_the_gui_never_writes_to_the_results_file(self):
        with open(attack.RESULTS_PATH, "rb") as fh:
            before = fh.read()
        self.app.load_saved_attack_results()
        self.app.notebook.select(gui.TAB_ATTACK)
        self.app._on_tab_changed()
        with open(attack.RESULTS_PATH, "rb") as fh:
            self.assertEqual(fh.read(), before)


class TestEfficiencyTab(GuiTestCase):
    def setUp(self):
        super().setUp()
        self.app._speed_results = None

    def test_the_saved_table_loads_when_the_tab_is_opened(self):
        self.app.notebook.select(gui.TAB_EFFICIENCY)
        self.app._on_tab_changed()
        saved = gui.read_benchmark_csv()
        self.assertEqual(len(self.app.speed_tree.get_children()), len(saved["table_a"]))
        self.assertGreater(len(self.app.chart_time.find_all()), 10)       # the charts were drawn
        self.assertGreater(len(self.app.chart_per_char.find_all()), 10)
        self.assertIn("Saved results", self.app.speed_source_var.get())
        self.assertEqual(self.app.speed_note_var.get(), gui.SPEED_HINT)
        self.assertEqual(self.app.speed_note_var.get(), "Median time per message length. Flat custom us/char = O(N).")

    def test_a_missing_csv_shows_a_friendly_red_line(self):
        missing = os.path.join(tempfile.gettempdir(), "nope_speed_phase7.csv")
        self.assertIsNone(self.app.load_saved_speed_results(path=missing))
        self.assertEqual(self.app.speed_note_var.get(), "Run python benchmark.py to create results/benchmark_results.csv")
        self.assertEqual(str(self.app.speed_note_label.cget("fg")), gui.RED)

    def test_there_is_only_a_quick_run_no_full_option_and_no_load_button(self):
        texts = {str(w.cget("text")) for w in all_widgets(self.app.root) if w.winfo_class() in ("TButton", "TRadiobutton")}
        self.assertIn("Run", texts)
        self.assertIn("Cancel", texts)
        for removed in ("Load saved results", "Quick (up to 10,000)", "Full (up to 100,000)"):
            self.assertNotIn(removed, texts)
        self.assertEqual(self.app.speed_bar.cget("maximum"), benchmark.count_cells(benchmark.QUICK_SETTINGS))

    def test_a_quick_run_can_be_cancelled(self):
        self.assertTrue(self.app.run_speed_test())
        self.assertFalse(self.app.run_speed_test())                  # a second start is ignored while busy
        self.assertTrue(self.app.cancel_speed_test())
        self.assertTrue(self.app.wait_until_idle(120))
        self.assertEqual(self.app.speed_note_var.get(), gui.SPEED_HINT)
        self.assertEqual(str(self.app.speed_run.cget("state")), "normal")
        self.assertEqual(str(self.app.speed_cancel.cget("state")), "disabled")
        self.assertIn("Cancelled", self.app.status_var.get())

    def test_a_quick_run_finishes_and_replaces_the_table(self):
        self.app.load_saved_speed_results()
        self.assertTrue(self.app.run_speed_test())
        self.assertTrue(self.app.wait_until_idle(180))
        self.assertIn("Quick run", self.app.speed_source_var.get())
        sizes = [int(self.app.speed_tree.item(i)["values"][0]) for i in self.app.speed_tree.get_children()]
        self.assertEqual(sizes, benchmark.QUICK_SETTINGS["sizes"])   # a quick run stops at the quick sizes
        self.assertLessEqual(max(sizes), 10000)
        self.assertEqual(float(self.app.speed_bar.cget("value")), float(self.app.speed_bar.cget("maximum")))
        # Opening the tab again must not wipe the run that was just made.
        self.app.notebook.select(gui.TAB_EFFICIENCY)
        self.app._on_tab_changed()
        self.assertIn("Quick run", self.app.speed_source_var.get())


class TestFourTabsAndDesign(GuiTestCase):
    def test_four_tabs_with_the_right_titles(self):
        self.assertEqual(self.app.notebook.index("end"), 4)
        titles = [self.app.notebook.tab(i, "text") for i in range(4)]
        self.assertIn(titles, (gui.TAB_TITLES_LONG, gui.TAB_TITLES_SHORT))      # long names, or short if they do not fit
        for title, words in zip(titles, (("Req 2", "Encrypt", "Decrypt"), ("Req 3", "Attack"),
                                         ("Req 4", "Efficiency"), ("Req 1", "Design"))):
            for word in words:
                self.assertIn(word, title)
        self.assertEqual(self.root.title(), "CT-486 NIS CCP - Vigenere + Rail Fence")
        self.assertEqual(self.root.minsize(), (950, 680))

    def test_the_long_titles_are_the_ones_asked_for(self):
        self.assertEqual(gui.TAB_TITLES_LONG, ["Req 2 \u00b7 Encrypt & Decrypt", "Req 3 \u00b7 Deliverable 2 \u00b7 Attack",
                                               "Req 4 \u00b7 Efficiency", "Req 1 \u00b7 Deliverable 1 \u00b7 Design"])

    def test_long_names_are_used_only_when_they_fit(self):
        from unittest import mock
        from tkinter import font as tkfont
        with mock.patch.object(tkfont.Font, "measure", return_value=40):
            self.assertEqual(self.app._choose_tab_titles(), gui.TAB_TITLES_LONG)
        with mock.patch.object(tkfont.Font, "measure", return_value=400):
            self.assertEqual(self.app._choose_tab_titles(), gui.TAB_TITLES_SHORT)

    def test_the_removed_features_are_really_gone(self):
        for name in ("start_tour", "tour_next", "tour_back", "tour_exit", "_build_tour_banner", "run_self_test",
                     "move_output_to_input", "copy_output", "run_experiments", "cancel_experiments",
                     "save_attack_csv", "attack_sub", "start_button", "selftest_label", "weak_label", "paste_text"):
            self.assertFalse(hasattr(self.app, name), name)
        for name in ("run_self_test_checks", "weak_key_note", "experiments_banner", "efficiency_banner", "is_protected"):
            self.assertFalse(hasattr(gui, name), name)
        shown = {str(w.cget("text")) for w in all_widgets(self.app.root) if w.winfo_class() in ("TButton", "TRadiobutton")}
        for removed in ("START HERE", "Run Self-Test", "Move output to input", "Copy output", "Save as CSV...",
                        "Load saved full results", "Paste my own ciphertext"):
            self.assertNotIn(removed, shown)
        self.assertEqual([w for w in all_widgets(self.app.root) if w.winfo_class() == "TNotebook"], [self.app.notebook])

    def test_each_tab_has_its_own_short_ready_message(self):
        messages = []
        for tab in range(4):
            self.app.notebook.select(tab)
            self.app._on_tab_changed()
            messages.append(self.app.status_var.get())
        self.assertEqual(messages[0], gui.READY_MESSAGES[gui.TAB_LOCK])
        self.assertEqual(messages[3], gui.READY_MESSAGES[gui.TAB_DESIGN])
        self.assertEqual(len(set(messages)), 4)
        self.assertTrue(all(m.startswith("Ready.") and m.count(". ") <= 1 for m in messages), messages)

    def test_a_tab_remembers_what_it_last_said(self):
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        said = self.app.status_var.get()
        self.assertTrue(said.startswith("Done in"))
        self.app.notebook.select(gui.TAB_ATTACK)
        self.app._on_tab_changed()
        self.assertEqual(self.app.status_var.get(), gui.READY_MESSAGES[gui.TAB_ATTACK])
        self.app.notebook.select(gui.TAB_LOCK)
        self.app._on_tab_changed()
        self.assertEqual(self.app.status_var.get(), said)

    def test_the_design_examples_match_cipher_py(self):
        self.app.notebook.select(gui.TAB_DESIGN)
        self.app._on_tab_changed()
        content = self.app.design_content()
        self.assertIn("HELLO + key CAT = " + cipher.vigenere_encrypt("HELLO", "CAT"), content)
        self.assertIn("ABCDEFGHIJ on 3 rails = " + cipher.rail_encrypt("ABCDEFGHIJ", 3), content)
        self.assertIn("JEENO", content)
        self.assertIn("AEIBDFHJCG", content)
        self.assertNotIn("WARNING", content)

    def test_the_design_page_shows_a_red_warning_if_an_example_disagrees(self):
        from unittest import mock
        with mock.patch.object(cipher, "rail_encrypt", lambda text, rails: text):
            self.app.refresh_design()
            self.assertIn("WARNING: the Stage 2 example does not match cipher.py", self.app.design_content())
            self.assertNotIn("AEIBDFHJCG", self.app.design_content())
            reds = [w for w in self.app.design_frame.winfo_children() if str(w.cget("fg")) == gui.RED]
            self.assertEqual(len(reds), 1)
        self.app.refresh_design()
        self.assertNotIn("WARNING", self.app.design_content())

    def test_the_design_page_numbers_follow_the_csv_files(self):
        from unittest import mock
        attack_data, speed_data = gui.read_attack_csv(), gui.read_benchmark_csv()
        for row in speed_data["table_a"]:
            row["ratio"] = 7.0
        with mock.patch.object(gui, "read_benchmark_csv", lambda path=None: speed_data):
            self.app.refresh_design()
        self.assertIn("Custom is about 7.0 times slower than Shift.", self.app.design_content())
        self.assertIn("works from about", self.app.design_content())
        self.app.refresh_design()

    def test_the_design_page_with_missing_files_does_not_crash(self):
        from unittest import mock
        nowhere = os.path.join(tempfile.gettempdir(), "nope_phase7_design.csv")
        with mock.patch.object(gui, "read_benchmark_csv", side_effect=FileNotFoundError), \
                mock.patch.object(gui, "read_attack_csv", side_effect=FileNotFoundError):
            self.app.refresh_design()
        content = self.app.design_content()
        self.assertIn("was not found", content)
        self.assertNotIn("times slower", content)
        self.app.refresh_design()

    def test_the_design_page_has_no_scrolling_and_is_short(self):
        tab = self.app.notebook.nametowidget(self.app.notebook.tabs()[gui.TAB_DESIGN])
        classes = {w.winfo_class() for w in all_widgets(tab)}
        self.assertFalse(classes & {"Text", "TScrollbar", "Scrollbar", "Canvas"}, classes)
        self.assertLessEqual(len(self.app.design_frame.winfo_children()), 12)


if __name__ == "__main__":
    unittest.main()
