from hashlib import sha256
from decimal import Decimal
from binascii import unhexlify, hexlify
import pprint
import unittest

from electrum.lnaddr import shorten_amount, unshorten_amount, LnAddr, lnencode, lndecode
from electrum.segwit_addr import bech32_encode, bech32_decode
from electrum import segwit_addr
from electrum.lnutil import UnknownEvenFeatureBits, LnFeatures, IncompatibleLightningFeatures
from electrum import constants

from . import ElectrumTestCase


RHASH=unhexlify('0001020304050607080900010203040506070809000102030405060708090102')
PAYMENT_SECRET=unhexlify('1111111111111111111111111111111111111111111111111111111111111111')
CONVERSION_RATE=1200
PRIVKEY=unhexlify('e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734')
PUBKEY=unhexlify('03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad')


class TestBolt11(ElectrumTestCase):
    def test_shorten_amount(self):
        tests = {
            Decimal(10)/10**12: '10p',
            Decimal(1000)/10**12: '1n',
            Decimal(1200)/10**12: '1200p',
            Decimal(123)/10**6: '123u',
            Decimal(123)/1000: '123m',
            Decimal(3): '3',
            Decimal(1000): '1000',
        }

        for i, o in tests.items():
            self.assertEqual(shorten_amount(i), o)
            assert unshorten_amount(shorten_amount(i)) == i

    @staticmethod
    def compare(a, b):

        if len([t[1] for t in a.tags if t[0] == 'h']) == 1:
            h1 = sha256([t[1] for t in a.tags if t[0] == 'h'][0].encode('utf-8')).digest()
            h2 = [t[1] for t in b.tags if t[0] == 'h'][0]
            assert h1 == h2

        # Need to filter out these, since they are being modified during
        # encoding, i.e., hashed
        a.tags = [t for t in a.tags if t[0] != 'h' and t[0] != 'n']
        b.tags = [t for t in b.tags if t[0] != 'h' and t[0] != 'n']

        assert b.pubkey.serialize() == PUBKEY, (hexlify(b.pubkey.serialize()), hexlify(PUBKEY))
        assert b.signature is not None

        # Unset these, they are generated during encoding/decoding
        b.pubkey = None
        b.signature = None

        assert a.__dict__ == b.__dict__, (pprint.pformat([a.__dict__, b.__dict__]))

    def test_roundtrip(self):
        longdescription = ('One piece of chocolate cake, one icecream cone, one'
                          ' pickle, one slice of swiss cheese, one slice of salami,'
                          ' one lollypop, one piece of cherry pie, one sausage, one'
                          ' cupcake, and one slice of watermelon')

        timestamp = 1615922274
        tests = [
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, tags=[('d', ''), ('9', 33282)]),
             "lnbc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdqq9qypqszpyrpe4tym8d3q87d43cgdhhlsrt78epu7u99mkzttmt2wtsx0304rrw50addkryfrd3vn3zy467vxwlmf4uz7yvntuwjr2hqjl9lw5cqwtp2dy"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('9', 0x28200)]),
             "lnbc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5xysxxatsyp3k7enxv4jsxqzpu9qy9qsqw8l2pulslacwjt86vle3sgfdmcct5v34gtcpfnujsf6ufqa7v7jzdpddnwgte82wkscdlwfwucrgn8z36rv9hzk5mukltteh0yqephqpk5vegu"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=Decimal('1'), tags=[('h', longdescription), ('9', 0x28200)]),
             "lnbc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq0jnua6dc4p984aeafs6ss7tjjj7553ympvg82qrjq0zgdqgtdvt5wlwkvw4ds5sn96nazp6ct9ts37tcw708kzkk4p8znahpsgp9tnspnycsf7"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription), ('9', 0x28200)]),
             "lntb1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy5826t0z3sn29z396pmr4kv73lcx0v7y6vas6h3pysmqllmzwgm5ps2t468gm4psj52usjy6y4xcry4k84n2zggs6f9agwg95454v6gqrwmh4f"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[
                ('r', [(unhexlify('029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('0102030405060708'), 1, 20, 3),
                       (unhexlify('039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'), unhexlify('030405060708090a'), 2, 30, 4)]),
                ('f', 'LKes97HFbh3dxrvhiMohYXyzYJPTK37n7u'),
                ('h', longdescription),
                ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqfnk063vsrgjx7l6td6v42skuxql7epn5tmrl4qte2e78nqnsjlgjg3sgkxreqex5fw4c9chnvtc2hykqnyxr84zwfr8f3d9q3h0nfdgqenlzvj"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', 'MLy36ApB4YZb2cBtTc1uYJhYsP2JkYokaf'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppj3a24vwu6r8ejrss3axul8rxldph2q7z9hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqqf6z4r7ruzr5txm5ln4netwa2f4x233tud7jy8gxrynyx07rxt7qm92yk2krlgwr7d8jknglur75sujeyapmda5nf3femrk2mep8a2cp4hlvup"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', 'ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfppqw508d6qejxtdg4y5r3zarvary0c5xw7khp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqy4wp73jma5uktd9y7yha56f98n2k0hxgnvp2qdcury00dapps3k3urgfy8tvv8jzwcafpy576msk5xx2hladf06m3s5mgx5msn4elfqqaaqjhk"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('f', 'ltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qmu8tk5'), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsqgt4gg9uktlpgnnuvczazusp5uwjv78na305ucsw06c8uk58e5stjqj9sz7fgavw0z688alt364js72mc9mg8yumhpes2dsmq5k9nr5qqddykxy"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('n', PUBKEY), ('h', longdescription), ('9', 0x28200)]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qy9qsq2y235rxw7v0gkn2t9ehc742tm3p22q2yjjykq4d85ze6g62yk60navxqz0ga96sqrszju8nlfajthem4gngxvyz4hwy39j4nqm8kv0qq9znxs7"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 2 + (1 << 9) + (1 << 15))]),
             "lnltc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqszxkdza3c2a8mx7htenxyj28tl9uhs6zd8pz8nec3n2s7k0zzas4cn6jcgnk4j49zu552kwlg6nz4lcl847d8g26nf6lxn4c0y7jmkkjsqt2wsey"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 8) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqg2wans8f6vkfd3l7zjv547hlc7wd7eqyxfwhtdudnkkgrpk6p9ffykwrvdtwm0aakaxujurdxgd7cllnfypmj22cvy7z333udg6zncgacqzmd2z9"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 15))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qypqs2dr525u5f4kjxdv0hq5c822qwxrtttjl4u586yl84x0kvvx66gz9ygy76005s5sjwgr7fp55ccsae47vpl4gqvwhc3exps964g743j5gqwtt68t"),
            (LnAddr(date=timestamp, paymenthash=RHASH, payment_secret=PAYMENT_SECRET,  amount=24, tags=[('h', longdescription), ('9', 10 + (1 << 9) + (1 << 14))]),
             "lnbc241ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrss2f8kr98446xls02yndup2ynwjh46u8kdeuuncexx2hnets0j0064nyq25gkd6jnttldzt5qqtszum5dufvuvryxt204w2p24557udxgcp0nlwtw"),
        ]
        # Some old tests follow that do not have payment_secret. Note that if the parser raised due to the lack of features/payment_secret,
        # old wallets that have these invoices saved (as paid/expired), could not be opened (though we could do a db upgrade and delete them).
        tests.extend([
            (LnAddr(date=timestamp, paymenthash=RHASH, tags=[('d', '')]),
             "lnltc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqqtxf4xmgwm6d57t2u47xcknw8mcmxgnx24c4vq3uxft5f0sgx4kv478rt4j350n2hjlq0qqwgkwqv54ujrjtmw2gahwyrzfqq572r64qpsrpjy4"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60)]),
             "lnltc1m1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuve3yl8e96v8ccdy5lgf4z8vdpmkzj228v2qxknwws2r00cwvqwhp2agvlqw4eklf8sjnvkeama0ke8nrlrc6nd4twspv5zhuy7hzqxgqd8tsep"),
            (LnAddr(date=timestamp, paymenthash=RHASH, amount=Decimal('1'), tags=[('h', longdescription)]),
             "lnltc11ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsz9dyzv7qgv60vrvj6hu8cyhj4epls6hwtgzgew82sqyhv0cjhnmjrr627cdjp4ejce0fps0q83505fjrh43enpwje3hty4kpu244trqp8snnu3"),
            (LnAddr(date=timestamp, paymenthash=RHASH, net=constants.BitcoinTestnet, tags=[('f', 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'), ('h', longdescription)]),
             "lntltc1ps9zprzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9pqjahusc5f4737qr4ke4tf6mnswpt689y07jhw8usmus07q2pd43f7ya5t82d9aq8ay2e7kwuat0wzp7hhfla9ghg9ytt38r8pynrgqdt4rpe"),

        ])

        # Roundtrip
        for lnaddr1, invoice_str1 in tests:
            invoice_str2 = lnencode(lnaddr1, PRIVKEY)
            self.assertEqual(invoice_str1, invoice_str2)
            lnaddr2 = lndecode(invoice_str2, net=lnaddr1.net)
            self.compare(lnaddr1, lnaddr2)

    def test_n_decoding(self):
        # We flip the signature recovery bit, which would normally give a different
        # pubkey.
        _, hrp, data = bech32_decode(
            lnencode(LnAddr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertNotEqual(lnaddr.pubkey.serialize(), PUBKEY)

        # But not if we supply expliciy `n` specifier!
        _, hrp, data = bech32_decode(
            lnencode(LnAddr(paymenthash=RHASH, payment_secret=PAYMENT_SECRET, amount=24, tags=[('d', ''), ('n', PUBKEY), ('9', 33282)]), PRIVKEY),
            ignore_long_length=True)
        data[-1] ^= 1
        lnaddr = lndecode(bech32_encode(segwit_addr.Encoding.BECH32, hrp, data), verbose=True)
        self.assertEqual(lnaddr.pubkey.serialize(), PUBKEY)

    def test_min_final_cltv_expiry_decoding(self):
        lnaddr = lndecode("lnsb500u1pdsgyf3pp5nmrqejdsdgs4n9ukgxcp2kcq265yhrxd4k5dyue58rxtp5y83s3qsp5qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsdqqcqzys9qypqsqp2h6a5xeytuc3fad2ed4gxvhd593lwjdna3dxsyeem0qkzjx6guk44jend0xq4zzvp6f3fy07wnmxezazzsxgmvqee8shxjuqu2eu0qpnvc95x",
                          net=constants.BitcoinSimnet)
        self.assertEqual(144, lnaddr.get_min_final_cltv_delta())

        lnaddr = lndecode("lntltc15u1p0m6lzupp5zqjthgvaad9mewmdjuehwddyze9d8zyxcc43zhaddeegt37sndgsdq4xysyymr0vd4kzcmrd9hx7cqp7xqrrss9qy9qsqsp5vlhcs24hwm747w8f3uau2tlrdkvjaglffnsstwyamj84cxuhrn2sd9wnsselxlsqyz5ktk0dafjj77ag862qqeqmldxd6nzx7z2q2ttsu073xujdvjjzwcullaxh5mfz3qmd558cf7l8m0e4rkq227cnsvcp2lx59z",
                          net=constants.BitcoinTestnet)
        self.assertEqual(30, lnaddr.get_min_final_cltv_delta())

    def test_min_final_cltv_expiry_roundtrip(self):
        for cltv in (1, 15, 16, 31, 32, 33, 150, 511, 512, 513, 1023, 1024, 1025):
            lnaddr = LnAddr(
                paymenthash=RHASH, payment_secret=b"\x01"*32, amount=Decimal('0.001'), tags=[('d', '1 cup coffee'), ('x', 60), ('c', cltv), ('9', 33282)])
            self.assertEqual(cltv, lnaddr.get_min_final_cltv_delta())
            invoice = lnencode(lnaddr, PRIVKEY)
            self.assertEqual(cltv, lndecode(invoice).get_min_final_cltv_delta())

    def test_features(self):
        lnaddr = lndecode("lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9qypqsztrz5v3jfnxskfv7g8chmyzyrfhf2vupcavuq5rce96kyt6g0zh337h206awccwp335zarqrud4wccgdn39vur44d8um4hmgv06aj0sgpdrv73z")
        self.assertEqual(33282, lnaddr.get_tag('9'))
        self.assertEqual(LnFeatures(33282), lnaddr.get_features())

    def test_payment_secret(self):
        lnaddr = lndecode("lnltc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsq8da9nsp6wq9ugrglqwvgzqn6tj6wr0u0fzwg57trnjd070ef6f6ykh6kykgtdg9umljul8ah85sy80jgz7f3jr5y2uu756s4a8pq80qpxe4kez")
        self.assertEqual((1 << 9) + (1 << 15) + (1 << 99), lnaddr.get_tag('9'))
        self.assertEqual(b"\x11" * 32, lnaddr.payment_secret)

    def test_validate_and_compare_features(self):
        lnaddr = lndecode("lnltc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsdq5vdhkven9v5sxyetpdees9q5sqqqqqqqqqqqqqqqpqsq8da9nsp6wq9ugrglqwvgzqn6tj6wr0u0fzwg57trnjd070ef6f6ykh6kykgtdg9umljul8ah85sy80jgz7f3jr5y2uu756s4a8pq80qpxe4kez")
        lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 15)))
        with self.assertRaises(IncompatibleLightningFeatures):
            lnaddr.validate_and_compare_features(LnFeatures((1 << 8) + (1 << 14) + (1 << 16)))
