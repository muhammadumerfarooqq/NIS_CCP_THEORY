"""Smoke tests for the GUI. The window is built but kept hidden (withdrawn).

If this computer has no display, Tk cannot start; then these tests are
SKIPPED, not failed. The pure helper functions in gui.py are tested in
tests/test_gui_helpers.py, which needs no display."""

import csv
import os
import tempfile
import unittest

try:
    import tkinter as tk
except ImportError as error:        # some Python installs have no tkinter
    raise unittest.SkipTest(f"tkinter is not installed: {error}")

import attack
import cipher
import gui

PLAIN = "DEFENDTHEEASTWALLOFTHECASTLE"
KEY = "CRYPTOGRAPHY"
STAGE1 = "FVDTGRZYETHQVNYAECLKHTJYUKJT"
FINAL = "FEEUVYTACYKDZHYLJJTRQNKTTGVH"


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
        self.app.clear_all()
        self.app.key_var.set("")
        self.app.rails_var.set("4")
        self.app.inline_var.set("")

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

    def test_lock_then_move_then_unlock_round_trip(self):
        self.fill("Meet me at the old stone bridge at dawn.", "LEMONSQUEEZE", 6)
        locked = self.app.do_encrypt()
        self.assertTrue(self.app.move_output_to_input())
        self.assertEqual(self.app.get_message(), locked)
        self.assertEqual(self.app.get_outputs()["final"], "")        # outputs were cleared
        self.assertEqual(self.app.do_decrypt(), "MEETMEATTHEOLDSTONEBRIDGEATDAWN")

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

    def test_copy_output(self):
        self.assertFalse(self.app.copy_output())                     # nothing to copy yet
        self.fill(PLAIN, KEY, 5)
        self.app.do_encrypt()
        self.assertTrue(self.app.copy_output())
        self.assertEqual(self.root.clipboard_get(), FINAL)

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


class TestBreakItTab(GuiTestCase):
    def setUp(self):
        super().setUp()
        # Every test starts from the window's default "Break It" settings, so
        # one test cannot leak its choices into the next.
        self.app.source_var.set("test")
        self.app.attack_var.set("freq")
        self.app.n_var.set("500")
        self.app.crib_size_var.set("30")
        self.app.paste_text.delete("1.0", "end")
        self.app.crib_entry_var.set("")
        self.app.attack_inline_var.set("")
        self.app._clear_attack_result()

    def test_frequency_attack_on_a_test_message(self):
        self.app.source_var.set("test")
        self.app.attack_var.set("freq")
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
        self.app.source_var.set("test")
        self.app.attack_var.set("kpa")
        self.app.n_var.set("500")
        self.app.crib_size_var.set("30")
        self.app.run_attack()
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertIn("Correct: yes", self.app.correct_var.get())
        self.assertEqual(self.app.result_vars["rails"].get(), str(self.app._truth["rails"]))
        self.assertEqual(self.app.result_vars["key"].get(), self.app._truth["key"])

    def test_attack_on_pasted_ciphertext(self):
        plain = (gui.attack.load_corpus())[:2500]
        _, ciphertext = cipher.custom_encrypt(plain, "KXVQMZPLTWNBRHDYAE", 4)
        self.app.source_var.set("paste")
        self.app.attack_var.set("kpa")
        self.app.paste_text.delete("1.0", "end")
        self.app.paste_text.insert("1.0", ciphertext[:50] + " \n" + ciphertext[50:])   # with whitespace
        self.app.crib_entry_var.set(plain[:30].lower())                                  # crib in lowercase
        self.app.run_attack()
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(self.app.result_vars["key"].get(), "KXVQMZPLTWNBRHDYAE")
        self.assertEqual(self.app.result_vars["rails"].get(), "4")
        self.assertEqual(self.app.correct_var.get(), "")             # pasted: the truth is unknown
        self.assertEqual(str(self.app.reveal_button.cget("state")), "disabled")

    def test_pasted_attack_needs_input_and_a_long_enough_crib(self):
        self.app.source_var.set("paste")
        self.app.attack_var.set("freq")
        self.app.paste_text.delete("1.0", "end")
        self.assertFalse(self.app.run_attack())
        self.assertIn("Paste a ciphertext", self.app.attack_inline_var.get())
        self.app.paste_text.insert("1.0", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4)
        self.app.attack_var.set("kpa")
        self.assertFalse(self.app.run_attack())
        self.assertIn("needs a crib", self.app.attack_inline_var.get())
        self.app.crib_entry_var.set("SHORT")                          # fewer than 10 letters
        self.app.run_attack()
        self.assertTrue(self.app.wait_until_idle(30))
        self.assertIn("rib too short", self.app.attack_inline_var.get())    # the attack's own plain message
        self.assertEqual(self.app.result_vars["key"].get(), "-")

    def test_bad_crib_size_is_rejected_inline(self):
        self.app.source_var.set("test")
        self.app.crib_size_var.set("5")
        self.assertFalse(self.app.run_attack())
        self.assertIn("between 10 and 40", self.app.attack_inline_var.get())


class TestExperimentsAndFiles(GuiTestCase):
    def test_load_saved_full_results_is_instant(self):
        results = self.app.load_saved_attack_results()
        self.assertIsNotNone(results)
        self.assertEqual([len(self.app.attack_trees[t].get_children()) for t in ("table1", "table2", "table3")],
                         [7, 7, 5])
        first = self.app.attack_trees["table1"].item(self.app.attack_trees["table1"].get_children()[0])["values"]
        self.assertEqual(len(first), 7)

    def test_missing_saved_results_gives_a_friendly_message(self):
        self.assertIsNone(self.app.load_saved_attack_results(path=os.path.join(tempfile.gettempdir(), "nope_x.csv")))
        self.assertIn("was not found", self.app.exp_note_var.get())
        self.assertEqual(str(self.app.exp_note_label.cget("fg")), gui.RED)       # errors are red

    def test_quick_experiments_run_finish_and_can_be_saved(self):
        self.app.exp_mode_var.set("quick")
        self.assertTrue(self.app.run_experiments())
        self.assertFalse(self.app.run_experiments())                 # a second start is ignored while busy
        self.assertTrue(self.app.wait_until_idle(180))
        self.assertNotEqual(str(self.app.exp_note_label.cget("fg")), gui.RED)    # no error
        self.assertEqual(self.app.exp_note_var.get(), "done (10 trials per row)")
        self.assertEqual([len(self.app.attack_trees[t].get_children()) for t in ("table1", "table2", "table3")],
                         [7, 7, 5])
        self.assertEqual(str(self.app.exp_run.cget("state")), "normal")
        self.assertEqual(float(self.app.exp_bar.cget("value")), 19.0)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "attack_results_gui.csv")
            self.assertEqual(self.app.save_attack_csv(path), path)
            with open(path, newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 19)
        self.assertEqual({r["trials"] for r in rows}, {"10"})

    def test_cancel_stops_the_experiments(self):
        self.app.exp_mode_var.set("full")                            # long, so cancel really matters
        self.assertTrue(self.app.run_experiments())
        self.assertTrue(self.app.cancel_experiments())
        self.assertTrue(self.app.wait_until_idle(120))
        self.assertEqual(self.app.exp_note_var.get(), "cancelled")
        self.assertEqual(str(self.app.exp_run.cget("state")), "normal")
        self.assertEqual(str(self.app.exp_cancel.cget("state")), "disabled")
        self.assertIn("Cancelled", self.app.status_var.get())

    def test_saving_never_overwrites_the_protected_result_files(self):
        self.app.load_saved_attack_results()
        with open(attack.RESULTS_PATH, "rb") as fh:
            before = fh.read()
        for protected in (attack.RESULTS_PATH, attack.RESULTS_PATH_QUICK):
            self.assertIsNone(self.app.save_attack_csv(protected))
            self.assertIn("protected", self.app.exp_note_var.get())
            self.assertEqual(str(self.app.exp_note_label.cget("fg")), gui.RED)
        # Same file reached by a different spelling of the path is still protected.
        sneaky = os.path.join(os.path.dirname(attack.RESULTS_PATH), "..", "results", "attack_results.csv")
        self.assertIsNone(self.app.save_attack_csv(sneaky))
        with open(attack.RESULTS_PATH, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_save_without_results_explains_why(self):
        self.app._attack_results = None
        self.assertIsNone(self.app.save_attack_csv())               # no dialog is opened
        self.assertIn("no results to save", self.app.exp_note_var.get())


class TestSpeedTab(GuiTestCase):
    def test_load_saved_speed_results(self):
        data = self.app.load_saved_speed_results()
        self.assertIsNotNone(data)
        self.assertEqual(len(self.app.speed_tree.get_children()), 6)
        self.assertGreater(len(self.app.chart_time.find_all()), 10)       # the chart was drawn
        self.assertGreater(len(self.app.chart_per_char.find_all()), 10)
        verdict = self.app._get_text(self.app.verdict_box)
        self.assertIn("log-log slope", verdict)
        self.assertIn("Peak memory", verdict)
        self.assertIn("N=100000", verdict)                       # every measured size is listed

    def test_missing_saved_speed_results(self):
        self.assertIsNone(self.app.load_saved_speed_results(path=os.path.join(tempfile.gettempdir(), "nope_y.csv")))
        self.assertIn("was not found", self.app.speed_note_var.get())
        self.assertEqual(str(self.app.speed_note_label.cget("fg")), gui.RED)

    def test_quick_speed_test_runs_and_can_be_cancelled(self):
        self.app.speed_mode_var.set("quick")
        self.assertTrue(self.app.run_speed_test())
        self.assertTrue(self.app.cancel_speed_test())
        self.assertTrue(self.app.wait_until_idle(120))
        self.assertEqual(self.app.speed_note_var.get(), "cancelled")
        self.assertEqual(str(self.app.speed_run.cget("state")), "normal")


class TestSelfTestAndHelp(GuiTestCase):
    def test_self_test_button_logic(self):
        checks, ms = self.app.run_self_test(show_window=False)
        self.assertTrue(all(passed for _, passed, _ in checks))
        self.assertGreater(ms, 0)
        self.assertIn("PASS", self.app.selftest_label.cget("text"))
        self.assertEqual(str(self.app.selftest_label.cget("fg")), gui.GREEN)

    def test_how_it_works_page_reads_numbers_from_the_csv_files(self):
        self.app.refresh_help()
        content = self.app.help_content()
        self.assertIn("Stage 1 - Vigenere", content)
        self.assertIn("AEIBDFHJCG", content)
        self.assertIn("JEENO", content)
        self.assertIn("100 trials per row", content)                  # read from attack_results.csv
        self.assertIn("log-log slope", content)                       # read from benchmark_results.csv

    def test_tabs(self):
        self.assertEqual(self.app.notebook.index("end"), 4)
        titles = [self.app.notebook.tab(i, "text").strip() for i in range(4)]
        self.assertIn(titles, (gui.TAB_TITLES_LONG, gui.TAB_TITLES_SHORT))      # long names, or short if they do not fit
        self.assertEqual(self.root.title(), "CT-486 NIS CCP - Vigenere + Rail Fence")
        self.assertEqual(self.root.minsize(), (950, 680))


if __name__ == "__main__":
    unittest.main()
