"""Phase 6 GUI tests: the START HERE guided tour, the tab names, the status
bar that is different on each tab, and the weak-key note.

Like tests/test_gui_smoke.py the window is built but kept hidden, nothing needs a
mouse (the tests call the same handlers the buttons call), and the whole file is
SKIPPED, not failed, if tkinter or a display is missing."""

import builtins
import os
import random
import statistics
import unittest
from unittest import mock

try:
    import tkinter as tk
    from tkinter import font as tkfont
except ImportError as error:        # some Python installs have no tkinter
    raise unittest.SkipTest(f"tkinter is not installed: {error}")

import attack
import cipher
import gui

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_CLEAN, _ = cipher.sanitize(gui.SAMPLE_MESSAGE)


def snapshot_of_the_project():
    """{relative path: (size, modified time)} for every file in the project (not .git or caches)."""
    seen = {}
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in files:
            path = os.path.join(folder, name)
            info = os.stat(path)
            seen[os.path.relpath(path, ROOT)] = (info.st_size, info.st_mtime_ns)
    return seen


class WriteSpy:
    """While active, records every file opened in a mode that could change it (w, a, x or +)."""

    def __enter__(self):
        self.writes = []
        real_open = builtins.open

        def spy(file, mode="r", *args, **kwargs):
            if set(str(mode)) & set("wax+"):
                self.writes.append((str(file), mode))
            return real_open(file, mode, *args, **kwargs)

        self._patch = mock.patch("builtins.open", spy)
        self._patch.start()
        return self

    def __exit__(self, *exc_info):
        self._patch.stop()


class GuiTestCase(unittest.TestCase):
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
        cls.app.close()

    def setUp(self):
        self.app.wait_until_idle(timeout=30)
        self.app.tour_exit()
        self.app.notebook.select(gui.TAB_LOCK)
        self.app.clear_all()
        self.app.key_var.set("")
        self.app.rails_var.set("4")
        self.app.inline_var.set("")
        self.app._status_memory = {tab: (m, "info") for tab, m in gui.READY_MESSAGES.items()}


class TestTourSteps(GuiTestCase):
    def test_step_1_locks_the_sample_with_the_real_cipher(self):
        with mock.patch.object(self.app, "do_encrypt", wraps=self.app.do_encrypt) as real_handler:
            text = self.app.start_tour()
        real_handler.assert_called_once()                              # the SAME handler as the Lock button
        stage1, final = cipher.custom_encrypt(SAMPLE_CLEAN, gui.SAMPLE_KEY, gui.SAMPLE_RAILS)
        out = self.app.get_outputs()
        self.assertEqual(out, {"cleaned": SAMPLE_CLEAN, "middle": stage1, "final": final})
        self.assertEqual(self.app.get_message(), gui.SAMPLE_MESSAGE)
        self.assertEqual(self.app.key_var.get(), gui.SAMPLE_KEY)
        self.assertEqual(self.app.rails_var.get(), str(gui.SAMPLE_RAILS))
        self.assertEqual(self.app.notebook.index(self.app.notebook.select()), gui.TAB_LOCK)
        for word in ("blue", "Stage 1", "orange", "Stage 2", "Show Working"):
            self.assertIn(word, text)
        self.assertEqual(self.app.tour_title.cget("text"), "Step 1 of 5")
        self.assertEqual(self.app.tour_text.cget("text"), text)
        self.assertIsNotNone(self.app.show_working())                  # Show Working has something to show
        self.assertEqual(self.app._tour_frame.winfo_manager(), "pack")    # the banner is on screen

    def test_step_2_moves_the_output_and_unlocks(self):
        self.app.start_tour()
        with mock.patch.object(self.app, "move_output_to_input", wraps=self.app.move_output_to_input) as move, \
                mock.patch.object(self.app, "do_decrypt", wraps=self.app.do_decrypt) as unlock:
            text = self.app.tour_next()
        move.assert_called_once()
        unlock.assert_called_once()
        _, final = cipher.custom_encrypt(SAMPLE_CLEAN, gui.SAMPLE_KEY, gui.SAMPLE_RAILS)
        self.assertEqual(self.app.get_message(), final)                # the ciphertext was moved to the input
        self.assertEqual(self.app.get_outputs()["final"], SAMPLE_CLEAN)    # and unlocking gave the original back
        self.assertEqual(self.app.get_outputs()["final"],
                         cipher.custom_decrypt(final, gui.SAMPLE_KEY, gui.SAMPLE_RAILS))
        self.assertIn("yes", self.app.check_label.cget("text"))
        self.assertEqual(str(self.app.check_label.cget("fg")), gui.GREEN)
        self.assertIn("original message is back", text)
        self.assertIn(self.app.check_label.cget("text"), text)         # quotes the real green check
        self.assertEqual(self.app.tour_title.cget("text"), "Step 2 of 5")

    def test_step_3_runs_the_real_frequency_attack(self):
        real_make_trial = attack._make_trial
        made = {}

        def fixed_trial(rng, corpus, n):
            made["trial"] = real_make_trial(random.Random(123), corpus, n)     # same message every run
            return made["trial"]

        self.app.start_tour()
        self.app.tour_next()
        with mock.patch.object(attack, "_make_trial", fixed_trial):
            text = self.app.tour_next()
            self.assertTrue(self.app.wait_until_idle(60))
        plaintext, key, rails, ciphertext = made["trial"]
        expected = attack.frequency_attack(ciphertext)                 # what the attack really returns
        self.assertEqual(self.app.notebook.index(self.app.notebook.select()), gui.TAB_ATTACK)
        self.assertEqual(self.app.attack_sub.index(self.app.attack_sub.select()), 0)
        self.assertEqual(self.app.attack_var.get(), "freq")
        self.assertEqual(self.app.n_var.get(), str(gui.DEFAULT_TEST_LENGTH))
        self.assertTrue(expected["ok"])
        self.assertEqual(self.app.result_vars["key"].get(), expected["key"])
        self.assertEqual(self.app.result_vars["rails"].get(), str(expected["rails"]))
        self.assertEqual(self.app.result_vars["guesses"].get(), str(expected["guesses"]))
        self.assertEqual(self.app.truth_var.get(), "")                 # the answer is still hidden ...
        self.assertEqual(str(self.app.reveal_button.cget("state")), "normal")    # ... until Reveal truth
        self.assertTrue(self.app.reveal_truth())
        self.assertIn(key, self.app.truth_var.get())
        self.assertIn("only the ciphertext", text)
        self.assertIn("Reveal truth", text)

    def test_step_4_loads_the_saved_attack_tables(self):
        self.app.start_tour()                                          # step 1
        self.app.tour_next()                                           # step 2
        self.app.tour_next()                                           # step 3 (starts an attack)
        self.assertTrue(self.app.wait_until_idle(60))
        with mock.patch.object(self.app, "load_saved_attack_results",
                               wraps=self.app.load_saved_attack_results) as handler:
            text = self.app.tour_next()
        handler.assert_called_once()
        saved = gui.read_attack_csv()
        self.assertEqual(self.app.attack_sub.index(self.app.attack_sub.select()), 1)    # the experiments page
        self.assertEqual([len(self.app.attack_trees[t].get_children()) for t in ("table1", "table2", "table3")],
                         [len(saved["table1"]), len(saved["table2"]), len(saved["table3"])])
        trials = saved["table1"][0]["trials"]
        self.assertIn(f"{trials} random trials", text)
        self.assertEqual(self.app.tour_title.cget("text"), "Step 4 of 5")

    def test_step_5_loads_the_saved_speed_results(self):
        self.app.start_tour()
        for _ in range(4):
            text = self.app.tour_next()
        saved = gui.read_benchmark_csv()
        self.assertEqual(self.app.notebook.index(self.app.notebook.select()), gui.TAB_EFFICIENCY)
        self.assertEqual(len(self.app.speed_tree.get_children()), len(saved["table_a"]))
        slope = {f["name"]: f for f in saved["fits"]}["Custom enc"]["loglog_slope"]
        ratio = statistics.median(r["ratio"] for r in saved["table_a"])
        self.assertIn(f"{slope:.2f}", text)
        self.assertIn(f"{ratio:.1f} times the Shift cipher", text)
        self.assertIn("O(N)", text)
        self.assertEqual(self.app.tour_title.cget("text"), "Step 5 of 5")
        self.assertEqual(str(self.app.tour_next_button.cget("state")), "disabled")    # the last step


class TestTourBannerNumbersComeFromTheFiles(GuiTestCase):
    def test_changed_files_change_the_banners(self):
        attack_data = gui.read_attack_csv()
        for table in attack_data.values():
            for row in table:
                row["trials"] = 7
        speed_data = gui.read_benchmark_csv()
        for row in speed_data["table_a"]:
            row["ratio"] = 3.0
        for fit in speed_data["fits"]:
            fit["loglog_slope"] = 1.234
            fit["verdict"] = "linear (slope 1.234): made up for this test"
        with mock.patch.object(gui, "read_attack_csv", lambda path=None: attack_data), \
                mock.patch.object(gui, "read_benchmark_csv", lambda path=None: speed_data):
            self.app.start_tour()
            text4 = self.app.tour_goto(4)
            text5 = self.app.tour_goto(5)
        self.assertIn("7 random trials", text4)          # not the 100 of the real file
        self.assertIn("3.0 times", text5)
        self.assertIn("1.23", text5)

    def test_a_slope_that_is_not_linear_is_not_called_a_straight_line(self):
        data = gui.read_benchmark_csv()
        for fit in data["fits"]:
            fit["loglog_slope"] = 1.9
            fit["verdict"] = "worse than linear (slope 1.900): quadratic-ish"
        text = gui.efficiency_banner(data)
        self.assertNotIn("straight line", text)
        self.assertIn("worse than linear", text)

    def test_missing_files_are_reported_not_invented(self):
        nowhere = os.path.join(ROOT, "results", "no_such_file_for_the_test.csv")
        with mock.patch.object(gui, "ATTACK_CSV", nowhere), mock.patch.object(gui, "BENCH_CSV", nowhere):
            self.app.start_tour()
            text4 = self.app.tour_goto(4)
            text5 = self.app.tour_goto(5)
        self.assertIn("was not found", text4)
        self.assertNotIn("random trials", text4)
        self.assertIn("was not found", text5)
        self.assertNotIn("times the Shift cipher", text5)
        self.assertEqual(self.app.tour_title.cget("text"), "Step 5 of 5")      # the tour still works


class TestTourControls(GuiTestCase):
    def test_back_next_and_exit(self):
        app = self.app
        self.assertIsNone(app.tour_next())                  # no tour running: Next does nothing
        self.assertFalse(app.tour_running())
        app.start_tour()
        self.assertEqual(str(app.tour_back_button.cget("state")), "disabled")      # step 1 has no Back
        self.assertEqual(app.tour_next() is not None, True)
        self.assertEqual(app.tour_title.cget("text"), "Step 2 of 5")
        app.tour_next()
        self.assertEqual(app.tour_title.cget("text"), "Step 3 of 5")
        app.tour_back()
        self.assertEqual(app.tour_title.cget("text"), "Step 2 of 5")
        self.assertEqual(app.notebook.index(app.notebook.select()), gui.TAB_LOCK)    # Back switched tab back
        app.tour_back()
        self.assertIsNone(app.tour_back())                  # already at step 1
        self.assertEqual(app.tour_title.cget("text"), "Step 1 of 5")
        for _ in range(4):
            app.tour_next()
        self.assertIsNone(app.tour_next())                  # already at step 5
        self.assertEqual(app.tour_title.cget("text"), "Step 5 of 5")
        app.tour_exit()
        self.assertFalse(app.tour_running())
        self.assertEqual(app._tour_frame.winfo_manager(), "")      # the banner is gone
        self.assertIsNone(app.tour_next())

    def test_window_is_usable_after_exit_and_the_tour_can_restart(self):
        self.app.start_tour()
        self.app.tour_next()
        self.app.tour_exit()
        self.app.set_message("Meet me at the old stone bridge at dawn")
        self.app.key_var.set("LEMONSQUEEZE")
        self.app.rails_var.set("6")
        self.assertEqual(self.app.do_encrypt(), cipher.custom_encrypt("MEETMEATTHEOLDSTONEBRIDGEATDAWN",
                                                                      "LEMONSQUEEZE", 6)[1])
        text = self.app.start_tour()                        # starting again begins at step 1
        self.assertEqual(self.app.tour_title.cget("text"), "Step 1 of 5")
        self.assertEqual(self.app._tour_frame.winfo_manager(), "pack")
        self.assertIn("blue", text)

    def test_the_tour_writes_nothing_to_disk(self):
        before = snapshot_of_the_project()
        with WriteSpy() as spy, mock.patch.object(gui.filedialog, "asksaveasfilename",
                                                  side_effect=AssertionError("the tour must not open a Save dialog")):
            self.app.start_tour()
            for _ in range(4):
                self.app.tour_next()
            self.assertTrue(self.app.wait_until_idle(60))       # the step-3 attack has finished
            self.app.tour_back()
            self.app.tour_exit()
            self.app.start_tour()
            self.app.tour_exit()
        self.assertEqual(spy.writes, [])
        self.assertEqual(snapshot_of_the_project(), before)     # no file created, changed or removed

    def test_start_here_button_is_on_the_top_bar_left_of_self_test(self):
        buttons = [w for w in self.app.start_button.master.pack_slaves() if w.winfo_class() == "TButton"]
        texts = [str(b.cget("text")) for b in buttons]
        # Packed from the right edge: the first button packed is the rightmost.
        self.assertEqual(texts, ["Run Self-Test", "START HERE"])
        self.assertEqual(str(self.app.start_button.cget("style")), "Start.TButton")


class TestTabsAndStatusBar(GuiTestCase):
    def test_tab_names_and_order(self):
        titles = [self.app.notebook.tab(i, "text") for i in range(4)]
        self.assertIn(titles, (gui.TAB_TITLES_LONG, gui.TAB_TITLES_SHORT))
        keywords = ["Req 2", "Req 3", "Req 4", "Req 1"]
        for title, word in zip(titles, keywords):
            self.assertIn(word, title)
        self.assertIn("Encrypt", titles[0])
        self.assertIn("Attack", titles[1])
        self.assertIn("Efficiency", titles[2])
        self.assertIn("Design", titles[3])

    def test_long_names_are_used_only_when_they_fit(self):
        with mock.patch.object(tkfont.Font, "measure", return_value=40):
            self.assertEqual(self.app._choose_tab_titles(), gui.TAB_TITLES_LONG)
        with mock.patch.object(tkfont.Font, "measure", return_value=400):
            self.assertEqual(self.app._choose_tab_titles(), gui.TAB_TITLES_SHORT)

    def test_each_tab_has_its_own_ready_message(self):
        messages = []
        for tab in range(4):
            self.app.notebook.select(tab)
            self.app._on_tab_changed()
            messages.append(self.app.status_var.get())
        self.assertEqual(messages, [gui.READY_MESSAGES[t] for t in range(4)])
        self.assertEqual(len(set(messages)), 4)                 # all different
        self.assertTrue(all(m.startswith("Ready.") for m in messages))
        self.assertIn(str(cipher.MIN_KEY_LENGTH), messages[0])

    def test_a_tab_remembers_what_it_last_said(self):
        self.app.set_message("Hello world, hello again")
        self.app.key_var.set("CRYPTOGRAPHY")
        self.app.do_encrypt()
        said = self.app.status_var.get()
        self.assertTrue(said.startswith("Done in"))
        self.app.notebook.select(gui.TAB_ATTACK)
        self.app._on_tab_changed()
        self.assertEqual(self.app.status_var.get(), gui.READY_MESSAGES[gui.TAB_ATTACK])    # not the lock message
        self.app.notebook.select(gui.TAB_LOCK)
        self.app._on_tab_changed()
        self.assertEqual(self.app.status_var.get(), said)

    def test_test_message_length_choices_include_50(self):
        values = list(self.app.n_combo.cget("values"))
        self.assertEqual(values, [str(n) for n in attack.TEXT_LENGTHS])
        self.assertEqual(values[0], "50")
        self.assertEqual(self.app.n_var.get(), "500")           # the default did not move

    def test_a_50_letter_test_message_can_be_attacked(self):
        self.app.source_var.set("test")
        self.app.attack_var.set("freq")
        self.app.n_var.set("50")
        self.assertTrue(self.app.run_attack())
        self.assertTrue(self.app.wait_until_idle(60))
        self.assertEqual(self.app.attack_inline_var.get(), "")
        self.assertTrue(self.app.result_vars["time"].get().endswith("ms"))
        self.app.n_var.set("500")


class TestWeakKeyNote(GuiTestCase):
    def test_orange_note_appears_for_a_weak_key_and_locking_still_works(self):
        self.app.set_message("Defend the east wall of the castle")
        self.app.key_var.set("AAAAAAAAAA")                      # valid (10 letters) but very weak
        self.assertEqual(self.app.weak_var.get(), gui.WEAK_KEY_NOTE)
        self.assertEqual(self.app.weak_var.get(),
                         "Weak key: very few different letters. Allowed, but easy to break.")
        self.assertEqual(str(self.app.weak_label.cget("fg")), gui.WEAK_FG)
        final = self.app.do_encrypt()                           # not blocked
        self.assertEqual(self.app.inline_text(), "")
        self.assertEqual(final, cipher.custom_encrypt("DEFENDTHEEASTWALLOFTHECASTLE", "AAAAAAAAAA", 4)[1])
        self.assertEqual(self.app.weak_var.get(), gui.WEAK_KEY_NOTE)    # still shown after locking

    def test_note_goes_away_for_a_good_key_and_for_an_empty_key(self):
        self.app.key_var.set("AAAAAAAAAA")
        self.assertNotEqual(self.app.weak_var.get(), "")
        self.app.key_var.set("CRYPTOGRAPHY")
        self.assertEqual(self.app.weak_var.get(), "")
        self.app.key_var.set("")
        self.assertEqual(self.app.weak_var.get(), "")


if __name__ == "__main__":
    unittest.main()
