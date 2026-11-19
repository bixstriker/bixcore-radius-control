"""Regression: DC01 Accounting-Start arrived ~19s after ACK request."""
import unittest
from unittest.mock import patch

from app import main
from sync import compose_control
from tests.test_omada_wired_pilot import helper


class WaitWindowTests(unittest.TestCase):
    def test_35_second_window_covers_observed_19_second_start(self):
        self.assertEqual(helper.CLEANUP_WAIT_SECONDS,35)
        before={"row_id":1430,"port":"3","mac":"020000000011",
                "username":"host/LAB-DC01.ad.example.test"}
        values=[{"cleanup":"waiting_new_start"} for _ in range(26)]
        values.append({"cleanup":"closed","new_session_id":"0000002F"})
        ticks=[0.0, *[19.0+i*0.01 for i in range(26)]]
        with patch.object(helper,"close_acked_predecessor",side_effect=values) as close, \
             patch.object(helper.time,"monotonic",side_effect=ticks), \
             patch.object(helper.time,"sleep") as sleep:
            result=helper.wait_for_accounting_successor("00000022",before,0,
                max_wait=helper.CLEANUP_WAIT_SECONDS,poll=.75)
        self.assertEqual(result["cleanup"],"closed")
        self.assertEqual(result["new_session_id"],"0000002F")
        self.assertEqual(close.call_count,27)
        self.assertEqual(sleep.call_count,26)

    def test_deadline_is_still_finite_and_does_not_close(self):
        with patch.object(helper,"close_acked_predecessor",return_value={
            "cleanup":"waiting_new_start"}) as close, \
             patch.object(helper.time,"monotonic",side_effect=[0,36]):
            result=helper.wait_for_accounting_successor("00000022",{},
                0,max_wait=35)
        self.assertEqual(result["cleanup"],"no_new_start")
        close.assert_called_once()

    def test_timeout_chain_exceeds_helper_window_with_headroom(self):
        ssh_timeout=compose_control.ACTIONS["omada_disconnect"][2]
        self.assertGreaterEqual(ssh_timeout,helper.CLEANUP_WAIT_SECONDS+7)
        source=main.omada_wired_disconnect.__code__
        self.assertIn(52,source.co_consts)
        self.assertGreaterEqual(52,ssh_timeout+5)


if __name__=="__main__":
    unittest.main()
