
def test_suite():
    import unittest
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    from openchange.tests import (test_provision, 
        test_mailbox)
    suite.addTests(loader.loadTestsFromModule(test_provision))
    suite.addTests(loader.loadTestsFromModule(test_mailbox))
    return suite
