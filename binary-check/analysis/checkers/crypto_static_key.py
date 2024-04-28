from analysis.checkers.basic import CheckerBase
from analysis.basic import Module, Function, ModuleAnalysisManager
from analysis.module_info_analysis import ModuleInfoAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.dominator_tree import DominatorTreeAnalysis
from analysis.value_set_analysis import SimpleValueSetAnalysis
from analysis.equivalent_analysis import EquivalentAnalysis
from analysis.return_var_analysis import ReturnVarAnalysis
from analysis.utils import get_call_ssa_instructions_to
from analysis.call_to_func_analysis import CallToFuncCallChain, CallToFuncAnalysis, \
    CallToFuncItem, CallToFuncList
from analysis.checkers.crypto_base.basic import CryptoReportItemBase, CallChainItem

from binaryninja import MediumLevelILInstruction, MediumLevelILOperation, \
    SSAVariable, Variable, Type
from utils.base_tool import safe_str, get_callee_name

import binaryninja
import typing
import logging
import copy

logger = logging.getLogger(__name__)


class CryptoStaticKeyReportItem(CryptoReportItemBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key : str = None
        self.key_address : int = None
    
    def set_key(self, key : str):
        if not self.key is None:
            logger.warning("key was reset")
        self.key = key
    
    def set_key_address(self, key_address : int):
        if not self.key_address is None:
            logger.warning("key address was reset")
        self.key_address = key_address
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        chain = copy.copy(self.chain)
        chain.reverse()
        rp = "%s : static key (%s)(%x)\n" % (self.desc, self.key, self.key_address)
        for item in chain:
            desc = '-----------------\nfunc : %s\ninstruction : %s\ntarget index : %d\n-----------------\n' % (
                item.func,
                item.insn,
                item.target_index
            )
            rp += desc
        
        rp += '\n\n'
        return rp

class CryptoStaticKeyChecker(CheckerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__max_depth = 3
        self.__depth = 3
        if 'depth' in kwargs:
            depth = kwargs['depth']
            assert isinstance(depth, int)
            self.__depth = depth
        if self.__depth > self.__max_depth:
            logger.warning('depth is too large')
            self.__depth = self.__max_depth
        if self.__depth < 0:
            logger.warning('depth is too small')
            self.__depth = self.__max_depth
    
    @staticmethod
    def get_checker_name()->str:
        return "CryptoStaticKey"
    
    def __validate_parameter(self, params : typing.List[MediumLevelILInstruction], index : int)->typing.Union[bool, int, str]:
        param_insn : MediumLevelILInstruction = params[index]
        if param_insn.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            addr = param_insn.constant
            static_key, _ = safe_str(self.__module, addr)
            return True, addr, static_key
        return False, -1, None

    def __check_set_xxx_key(self, call_to_func_analysis : CallToFuncAnalysis, function_name : str, param_index : int, tag : str):
        results : CallToFuncList = call_to_func_analysis.get_call_to_func(function_name, param_index)
        if len(results) == 0:
            return
        
        for chain in results:
            #wtf?
            assert len(chain) != 0
            issue = CryptoStaticKeyReportItem()
            for item in chain:
                issue.push(item.owner, item.instruction, item.target_index)
            last_item = chain[-1]
            state, addr, static_key = self.__validate_parameter(last_item.instruction.params, last_item.index)
            if state:
                issue.set_desc(tag)
                issue.set_key_address(addr)
                issue.set_key(static_key)
                self.report(issue)
        

    def run_on_module(self, module: Module, mam: ModuleAnalysisManager):
        self.__module : Module = module
        self.__mam : ModuleAnalysisManager = mam
        
        call_to_func_analysis : CallToFuncAnalysis = mam.get_module_analysis(CallToFuncAnalysis, module)

        """nettle
        """
        self.__check_set_xxx_key(call_to_func_analysis, "aes192_set_encrypt_key", 1, "nettle : aes192_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "aes128_set_encrypt_key", 1, "nettle : aes128_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "aes256_set_encrypt_key", 1, "nettle : aes256_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "camellia128_set_encrypt_key", 1, "nettle : camellia128_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "camellia192_set_encrypt_key", 1, "nettle : camellia192_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "camellia256_set_encrypt_key", 1, "nettle : camellia256_set_encrypt_key")
        self.__check_set_xxx_key(call_to_func_analysis, "aes_set_encrypt_key", 1, "nettle : aes_set_encrypt_key")
        
        """tiny-AES-c
        """

        """void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "AES_init_ctx", 1, "tiny-AES-c : AES_init_ctx")
        
        """void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "AES_init_ctx_iv", 1, "tiny-AES-c : AES_init_ctx_iv")

        """mbedtls
        """
        
        """int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_aes_setkey_enc", 1, "mbedtls : mbedtls_aes_setkey_enc")
        
        """int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_aes_setkey_dec", 1, "mbedtls : mbedtls_aes_setkey_dec")

        """int mbedtls_aes_xts_setkey_enc( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_aes_xts_setkey_enc", 1, "mbedtls : mbedtls_aes_xts_setkey_enc")

        """int mbedtls_aes_xts_setkey_dec( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_aes_xts_setkey_dec", 1, "mbedtls : mbedtls_aes_xts_setkey_dec")

        """void mbedtls_arc4_setup( mbedtls_arc4_context *ctx, const unsigned char *key,
                 unsigned int keylen );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_arc4_setup", 1, "mbedtls : mbedtls_arc4_setup")

        """int mbedtls_chacha20_setkey( mbedtls_chacha20_context *ctx,
                             const unsigned char key[32] );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_chacha20_setkey", 1, "mbedtls : mbedtls_chacha20_setkey")

        """int mbedtls_chachapoly_setkey( mbedtls_chachapoly_context *ctx,
                               const unsigned char key[32] );
        """
        self.__check_set_xxx_key(call_to_func_analysis, "mbedtls_chachapoly_setkey", 1, "mbedtls : mbedtls_chachapoly_setkey")

        """monocypher
        """

        """void crypto_poly1305(uint8_t        mac[16],
                     const uint8_t *message, size_t message_size,
                     const uint8_t  key[32]);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_poly1305", 3, "monocypher : crypto_poly1305")

        """void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const uint8_t      key[32],
                            const uint8_t      nonce[24]);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_chacha20_x_init", 1, "monocypher : crypto_chacha20_x_init")

        """void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const uint8_t      key[32],
                          const uint8_t      nonce[8]);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_chacha20_init", 1, "monocypher : crypto_chacha20_init")

        """void crypto_chacha20_H(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_chacha20_H", 1, "monocypher : crypto_chacha20_H")

        """void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t    key[32],
                      const uint8_t    nonce[24]);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_lock_init", 1, "monocypher : crypto_lock_init")

        """libtomcrypt
        """
        
        """int hash_memory(int hash,
                const unsigned char *in,  unsigned long inlen,
                      unsigned char *out, unsigned long *outlen);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "hash_memory", 1, "libtomcrypt : hash_memory")

        """int ctr_start(               int   cipher,
              const unsigned char *IV,
              const unsigned char *key,       int keylen,
                             int  num_rounds, int ctr_mode,
                   symmetric_CTR *ctr);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "ctr_start", 2, "libtomcrypt : ctr_start")

        """libsodium
        """

        """int crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                           const unsigned char *n, const unsigned char *k)
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_stream_chacha20", 3, "libsodium : crypto_stream_chacha20")

        """int crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
                          const unsigned char *n, const unsigned char *k)
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_stream_salsa20", 3, "libsodium : crypto_stream_salsa20")

        """int crypto_stream_salsa2012(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_stream_salsa2012", 3, "libsodium : crypto_stream_salsa2012")

        """int crypto_stream_xchacha20(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_stream_xchacha20", 3, "libsodium : crypto_stream_xchacha20")

        """int crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
                           const unsigned char *n, const unsigned char *k)
        """
        self.__check_set_xxx_key(call_to_func_analysis, "crypto_stream_xsalsa20", 3, "libsodium : crypto_stream_xsalsa20")

        """crypto-algorithms
        """

        """void aes_key_setup(const BYTE key[],          // The key, must be 128, 192, or 256 bits
                   WORD w[],                  // Output key schedule to be used later
                   int keysize);              // Bit length of the key, 128, 192, or 256
        """
        self.__check_set_xxx_key(call_to_func_analysis, "aes_key_setup", 0, "crypto-algorithms : aes_key_setup")

        """void blowfish_key_setup(const BYTE user_key[], BLOWFISH_KEY *keystruct, size_t len);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "blowfish_key_setup", 0, "crypto-algorithms : blowfish_key_setup")

        """void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "des_key_setup", 0, "crypto-algorithms : des_key_setup")

        """void three_des_key_setup(const BYTE key[], BYTE schedule[][16][6], DES_MODE mode);
        """
        self.__check_set_xxx_key(call_to_func_analysis, "three_des_key_setup", 0, "crypto-algorithms : three_des_key_setup")

        






