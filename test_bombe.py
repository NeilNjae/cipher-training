import unittest
import collections

from enigma import *

class LetterTransformerTest(unittest.TestCase):

    def test_maps1(self):
        lt = LetterTransformer([('z', 'a')] + \
            list(zip(string.ascii_lowercase, string.ascii_lowercase[1:])),
            raw_transform = True)
        self.assertEqual(lt.forward_map, 
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0])
        self.assertEqual(lt.backward_map, 
            [25, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])


    def test_maps2(self):
        lt = LetterTransformer(cat(collections.OrderedDict.fromkeys('zyxwc' + string.ascii_lowercase)))
        self.assertEqual(lt.forward_map, 
            [25, 24, 23, 22, 2, 0, 1, 3, 4, 5, 6, 7, 8, 9, 
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21])
        self.assertEqual(lt.backward_map,
            [5, 6, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
            17, 18, 19, 20, 21, 22, 23, 24, 25, 3, 2, 1, 0])

    def test_transform(self):
        lt = LetterTransformer(cat(collections.OrderedDict.fromkeys('zyxwc' + string.ascii_lowercase)))
        self.assertEqual(cat(lt.forward(l) for l in string.ascii_lowercase),
            'zyxwcabdefghijklmnopqrstuv')
        self.assertEqual(cat(lt.backward(l) for l in string.ascii_lowercase),
            'fgehijklmnopqrstuvwxyzdcba')


class PlugboardTest(unittest.TestCase):
    def setUp(self):
        self.pb = Plugboard('ua pf rq so ni ey bg hl tx zj'.upper())

    def test_maps(self):
        self.assertEqual(self.pb.forward_map, 
            [20, 6, 2, 3, 24, 15, 1, 11, 13, 25, 10, 7, 12, 
            8, 18, 5, 17, 16, 14, 23, 0, 21, 22, 19, 4, 9])
        self.assertEqual(self.pb.forward_map, self.pb.backward_map)

    def test_transform(self):
        self.assertEqual(cat(self.pb.forward(l) 
                for l in string.ascii_lowercase),
            'ugcdypblnzkhmisfrqoxavwtej')
        self.assertEqual(cat(self.pb.backward(l) 
                for l in string.ascii_lowercase),
            'ugcdypblnzkhmisfrqoxavwtej')


class ReflectorTest(unittest.TestCase):
    def setUp(self):
        self.ref = Reflector(reflector_b_spec)

    def test_maps(self):
        self.assertEqual(self.ref.forward_map, 
            [24, 17, 20, 7, 16, 18, 11, 3, 15, 23, 13, 6, 14, 
            10, 12, 8, 4, 1, 5, 25, 2, 22, 21, 9, 0, 19])
        self.assertEqual(self.ref.forward_map, self.ref.backward_map)

    def test_transform(self):
        self.assertEqual(cat(self.ref.forward(l) 
                for l in string.ascii_lowercase),
            'yruhqsldpxngokmiebfzcwvjat')
        self.assertEqual(cat(self.ref.backward(l) 
                for l in string.ascii_lowercase),
            'yruhqsldpxngokmiebfzcwvjat')


class SimpleWheelTest(unittest.TestCase):
    def test_init1(self):
        rotor_1_transform = list(zip(string.ascii_lowercase, 
            'EKMFLGDQVZNTOWYHXUSPAIBRCJ'.lower()))
        wheel_1 = SimpleWheel(rotor_1_transform, raw_transform=True)
        self.assertEqual(cat(wheel_1.forward(l) 
                for l in string.ascii_lowercase),
            'ekmflgdqvzntowyhxuspaibrcj')
        self.assertEqual(cat(wheel_1.backward(l) 
                for l in string.ascii_lowercase),
            'uwygadfpvzbeckmthxslrinqoj')

    def test_init2(self):
        wheel_2 = SimpleWheel(wheel_ii_spec)
        self.assertEqual(cat(wheel_2.forward(l) 
                for l in string.ascii_lowercase),
            'ajdksiruxblhwtmcqgznpyfvoe')
        self.assertEqual(cat(wheel_2.backward(l) 
                for l in string.ascii_lowercase),
            'ajpczwrlfbdkotyuqgenhxmivs')

    def test_advance(self):
        wheel_3 = SimpleWheel(wheel_iii_spec)
        wheel_3.set_position('a')
        wheel_3.advance()
        self.assertEqual(cat(wheel_3.forward(l) 
                for l in string.ascii_lowercase),
            'cegikboqswuymxdhvfzjltrpna')
        self.assertEqual(cat(wheel_3.backward(l) 
                for l in string.ascii_lowercase),
            'zfaobrcpdteumygxhwivkqjnls')
        self.assertEqual(wheel_3.position, 1)
        self.assertEqual(wheel_3.position_l, 'b')

        for _ in range(24): wheel_3.advance()

        self.assertEqual(wheel_3.position, 25)
        self.assertEqual(wheel_3.position_l, 'z')

        self.assertEqual(cat(wheel_3.forward(l) 
                for l in string.ascii_lowercase),
            'pcegikmdqsuywaozfjxhblnvtr')
        self.assertEqual(cat(wheel_3.backward(l) 
                for l in string.ascii_lowercase),
            'nubhcqdterfvgwoaizjykxmslp')

        wheel_3.advance()
        self.assertEqual(wheel_3.position, 0)
        self.assertEqual(wheel_3.position_l, 'a')

    
        self.assertEqual(cat(wheel_3.forward(l) 
                for l in string.ascii_lowercase),
            'bdfhjlcprtxvznyeiwgakmusqo')
        self.assertEqual(cat(wheel_3.backward(l) 
                for l in string.ascii_lowercase),
            'tagbpcsdqeufvnzhyixjwlrkom')


class SimpleWheelTest(unittest.TestCase):
    def test_init1(self):
        wheel = Wheel(wheel_iii_spec, wheel_iii_pegs, position='b', 
            ring_setting=1)
        self.assertEqual(wheel.position, 1)
        self.assertEqual(wheel.peg_positions, [20])
        self.assertEqual(wheel.position_l, 'b')

        wheel.advance()
        self.assertEqual(wheel.position, 2)
        self.assertEqual(wheel.peg_positions, [19])
        self.assertEqual(wheel.position_l, 'c')

    def test_init2(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        self.assertEqual(wheel.position, 25)
        self.assertIn(11, wheel.peg_positions)
        self.assertIn(24, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'b')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'xkqhwpvngzrcfoiaselbtymjdu')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'ptlyrmidoxbswhnfckquzgeavj')


    def test_advance(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        wheel.advance()

        self.assertEqual(wheel.position, 0)
        self.assertIn(10, wheel.peg_positions)
        self.assertIn(23, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'c')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'jpgvoumfyqbenhzrdkasxlictw')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'skxqlhcnwarvgmebjptyfdzuio')

    def test_advance_23(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        for _ in range(23):
            wheel.advance()

        self.assertEqual(wheel.position, 22)
        self.assertIn(1, wheel.peg_positions)
        self.assertIn(14, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'y')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'mgxantkzsyqjcufirldvhoewbp')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'dymswobuplgraevzkqifntxcjh')

    def test_advance_24(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        for _ in range(24):
            wheel.advance()

        self.assertEqual(wheel.position, 23)
        self.assertIn(0, wheel.peg_positions)
        self.assertIn(13, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'z')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'fwzmsjyrxpibtehqkcugndvaol')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'xlrvnatokfqzduyjphemswbigc')

    def test_advance_25(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        for _ in range(25):
            wheel.advance()

        self.assertEqual(wheel.position, 24)
        self.assertIn(25, wheel.peg_positions)
        self.assertIn(12, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'a')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'vylrixqwohasdgpjbtfmcuznke')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'kqumzsnjepyctxiogdlrvahfbw')

    def test_advance_26(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        for _ in range(26):
            wheel.advance()

        self.assertEqual(wheel.position, 25)
        self.assertIn(24, wheel.peg_positions)
        self.assertIn(11, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'b')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'xkqhwpvngzrcfoiaselbtymjdu')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'ptlyrmidoxbswhnfckquzgeavj')


    def test_advance_27(self):
        wheel = Wheel(wheel_vi_spec, wheel_vi_pegs, position='b', 
            ring_setting=3)
        for _ in range(27):
            wheel.advance()

        self.assertEqual(wheel.position, 0)
        self.assertIn(23, wheel.peg_positions)
        self.assertIn(10, wheel.peg_positions)
        self.assertEqual(wheel.position_l, 'c')
        self.assertEqual(cat(wheel.forward(l) 
                for l in string.ascii_lowercase),
            'jpgvoumfyqbenhzrdkasxlictw')
        self.assertEqual(cat(wheel.backward(l) 
                for l in string.ascii_lowercase),
            'skxqlhcnwarvgmebjptyfdzuio')

class EnigmaTest(unittest.TestCase):

    def setUp(self):
        self.enigma = Enigma(reflector_b_spec, 
                wheel_i_spec, wheel_i_pegs, 
                wheel_ii_spec, wheel_ii_pegs, 
                wheel_iii_spec, wheel_iii_pegs, 
                1, 1, 1, 
                '')

        # Setting sheet line 31 from http://www.codesandciphers.org.uk/enigma/enigma3.htm
        # Enigma simulation settings are 
        # http://enigma.louisedade.co.uk/enigma.html?m3;b;b153;AFTX;AJEU;AU-BG-EY-FP-HL-IN-JZ-OS-QR-TX
        self.enigma31 = Enigma(reflector_b_spec, 
                wheel_i_spec, wheel_i_pegs, 
                wheel_v_spec, wheel_v_pegs, 
                wheel_iii_spec, wheel_iii_pegs, 
                6, 20, 24, 
                'ua pf rq so ni ey bg hl tx zj')


    def test_middle_advance(self):
        self.enigma.set_wheels('a', 'a', 't')
        self.assertEqual(self.enigma.wheel_positions, (0, 0, 19))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'aat')
        self.assertEqual(self.enigma.peg_positions, ([16], [4], [2]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase), 
            'puvioztjdhxmlyeawsrgbcqknf')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 0, 20))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'aau')
        self.assertEqual(self.enigma.peg_positions, ([16], [4], [1]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'baigpldqcowfyzjehvtsxrkumn')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 0, 21))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'aav')
        self.assertEqual(self.enigma.peg_positions, ([16], [4], [0]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'mnvfydiwgzsoablrxpkutchqej')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 1, 22))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'abw')
        self.assertEqual(self.enigma.peg_positions, ([16], [3], [25]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'ulfopcykswhbzvderqixanjtgm')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 1, 23))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'abx')
        self.assertEqual(self.enigma.peg_positions, ([16], [3], [24]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'qmwftdyovursbzhxaklejicpgn')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 1, 24))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'aby')
        self.assertEqual(self.enigma.peg_positions, ([16], [3], [23]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'oljmzxrvucybdqasngpwihtfke')


    def test_double_advance(self):
        self.enigma.set_wheels('a', 'd', 't')
        self.assertEqual(self.enigma.wheel_positions, (0, 3, 19))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'adt')
        self.assertEqual(self.enigma.peg_positions, ([16], [1], [2]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'zcbpqxwsjiuonmldethrkygfva')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 3, 20))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'adu')
        self.assertEqual(self.enigma.peg_positions, ([16], [1], [1]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'ehprawjbngotxikcsdqlzyfmvu')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 3, 21))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'adv')
        self.assertEqual(self.enigma.peg_positions, ([16], [1], [0]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'eqzxarpihmnvjkwgbfuyslodtc')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (0, 4, 22))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'aew')
        self.assertEqual(self.enigma.peg_positions, ([16], [0], [25]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'qedcbtpluzmhkongavwfirsyxj')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (1, 5, 23))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'bfx')
        self.assertEqual(self.enigma.peg_positions, ([15], [25], [24]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'iwuedhsfazqxytvrkpgncoblmj')

        self.enigma.advance()
        self.assertEqual(self.enigma.wheel_positions, (1, 5, 24))
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'bfy')
        self.assertEqual(self.enigma.peg_positions, ([15], [25], [23]))
        self.assertEqual(cat(self.enigma.lookup(l) for l in string.ascii_lowercase),
            'baknstqzrmcxjdvygiefwoulph')


    def test_simple_encipher(self):
        self.enigma.set_wheels('a', 'a', 'a')
        ct = self.enigma.encipher('testmessage')
        self.assertEqual(ct, 'olpfhnvflyn')

        self.enigma.set_wheels('a', 'd', 't')
        ct = self.enigma.encipher('testmessage')
        self.assertEqual(ct, 'lawnjgpwjik')

        self.enigma.set_wheels('b', 'd', 'q')
        ct = self.enigma.encipher('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        self.assertEqual(ct, 
            'kvmmwrlqlqsqpeugjrcxzwpfyiyybwloewrouvkpoztceuwtfjzqwpbqldttsr')
        self.assertEqual(cat(self.enigma.wheel_positions_l), 'cha')


    def test_advance_with_ring_settings(self):
        self.enigma31.set_wheels('j', 'e', 'u')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (4, 11, 24))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jev')
        self.assertEqual(self.enigma31.peg_positions, ([7], [21], [0]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'mvqjlyowkdieasgzcunxrbhtfp')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (4, 12, 25))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jfw')
        self.assertEqual(self.enigma31.peg_positions, ([7], [20], [25]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'sjolzuyvrbwdpxcmtiaqfhknge')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (4, 12, 0))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jfx')
        self.assertEqual(self.enigma31.peg_positions, ([7], [20], [24]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'qrxedkoywufmlvgsabpzjnicht')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (4, 12, 1))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jfy')
        self.assertEqual(self.enigma31.peg_positions, ([7], [20], [23]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'hpsukliagqefwvtbjxcodnmrzy')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (4, 12, 2))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jfz')
        self.assertEqual(self.enigma31.peg_positions, ([7], [20], [22]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'zevnbpyqowrtxdifhkulscjmga')


    def test_advance_with_ring_settings_2(self):
        self.enigma31.set_wheels('i', 'd', 'z')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 3))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ida')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [21]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'ikhpqrvcambzjondefwyxgsutl')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 4))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idb')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [20]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'cdabskhgzwfmlqvunyexpojtri')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 5))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idc')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [19]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'pcbwiqhgemyvjsuaftnroldzkx')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 6))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idd')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [18]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'xcbfvdnouptmlghjzwykierasq')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 7))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ide')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [17]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'xfvglbdynuseriwqpmkzjcoaht')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 8))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idf')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [16]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'tfpqlbouynsewjgcdxkahzmriv')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 9))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idg')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [15]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'cjaunvlwtbygzexrspqidfhokm')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 10))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idh')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [14]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'yltxkrqvowebzpingfucshjdam')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 11))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idi')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [13]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'myktluzrnxceaiqsohpdfwvjbg')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 12))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idj')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [12]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'pynjrmiugdqxfcvakewzhoslbt')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 13))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idk')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [11]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'mwvedyplnoxhaijgrqtszcbkfu')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 14))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idl')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [10]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'qcbrfeutvoxpnmjladzhgiykws')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 15))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idm')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [9]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'dnoahryetsmukbcvwfjilpqzgx')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 16))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idn')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [8]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'nidcfehgbqsovalyjzkxwmutpr')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 17))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ido')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [7]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'joifxdulcarhzpbntkwqgysevm')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 18))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idp')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [6]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'ptnlsxvozmwdjchayuebrgkfqi')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 19))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idq')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [5]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'slwopzqnmxybihdeguavrtcjkf')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 20))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idr')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [4]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'hcbedwlamzogixkytsrqvufnpj')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 21))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ids')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [3]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'odxbjwzrmelkisavuhnyqpfctg')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 22))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idt')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [2]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'udgbfeclrwnhxksvtioqapjmzy')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 23))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idu')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [1]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'nrdczqxmowvshaiufblypkjgte')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 10, 24))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'idv')
        self.assertEqual(self.enigma31.peg_positions, ([8], [22], [0]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'hkifjdoacebqtzgulyvmpsxwrn')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 11, 25))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'iew')
        self.assertEqual(self.enigma31.peg_positions, ([8], [21], [25]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'yptzuhofqvnmlkgbixwcejsrad')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 11, 0))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'iex')
        self.assertEqual(self.enigma31.peg_positions, ([8], [21], [24]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'vkdcwhqfjibzsptngumoraeyxl')

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (3, 11, 1))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'iey')
        self.assertEqual(self.enigma31.peg_positions, ([8], [21], [23]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'wenpbqrouxlkychdfgzvitajms')

    def test_double_advance_with_ring_settings_2(self):
        self.enigma31.set_wheels('a', 'y', 't')
        self.assertEqual(self.enigma31.wheel_positions, (21, 5, 22))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ayt')
        self.assertEqual(self.enigma31.peg_positions, ([16], [1], [2]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (21, 5, 23))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ayu')
        self.assertEqual(self.enigma31.peg_positions, ([16], [1], [1]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (21, 5, 24))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'ayv')
        self.assertEqual(self.enigma31.peg_positions, ([16], [1], [0]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (21, 6, 25))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'azw')
        self.assertEqual(self.enigma31.peg_positions, ([16], [0], [25]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 7, 0))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bax')
        self.assertEqual(self.enigma31.peg_positions, ([15], [25], [24]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 7, 1))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bay')
        self.assertEqual(self.enigma31.peg_positions, ([15], [25], [23]))  

        self.enigma31.set_wheels('a', 'z', 't')
        self.assertEqual(self.enigma31.wheel_positions, (21, 6, 22))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'azt')
        self.assertEqual(self.enigma31.peg_positions, ([16], [0], [2]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 7, 23))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bau')
        self.assertEqual(self.enigma31.peg_positions, ([15], [25], [1]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 7, 24))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bav')
        self.assertEqual(self.enigma31.peg_positions, ([15], [25], [0]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 8, 25))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bbw')
        self.assertEqual(self.enigma31.peg_positions, ([15], [24], [25]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 8, 0))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bbx')
        self.assertEqual(self.enigma31.peg_positions, ([15], [24], [24]))

        self.enigma31.advance()
        self.assertEqual(self.enigma31.wheel_positions, (22, 8, 1))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'bby')
        self.assertEqual(self.enigma31.peg_positions, ([15], [24], [23]))


    def test_encipher_with_ring(self):

        self.enigma31.set_wheels('i', 'z', 'd')
        ct = self.enigma31.encipher('verylongtestmessagewithanextrabitofmessageforgoodmeasure')
        self.assertEqual(ct, 
            'apocwtjuikurcfivlozvhffkoacxufcekthcvodfqpxdjqyckdozlqki')
        self.assertEqual(self.enigma31.wheel_positions, (4, 9, 10))
        self.assertEqual(cat(self.enigma31.wheel_positions_l), 'jch')
        self.assertEqual(self.enigma31.peg_positions, ([7], [23], [14]))
        self.assertEqual(cat(self.enigma31.lookup(l) for l in string.ascii_lowercase),
            'mopnigfuesqwadbcktjrhylzvx')

        self.enigma31.set_wheels('i', 'z', 'd')
        pt = self.enigma31.decipher('apocwtjuikurcfivlozvhffkoacxufcekthcvodfqpxdjqyckdozlqki')
        self.assertEqual(pt, 
            'verylongtestmessagewithanextrabitofmessageforgoodmeasure')

if __name__ == '__main__':
    unittest.main()