package com.timtrense.quic.impl.base;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.timtrense.quic.ProtocolVersion;
import lombok.Data;
import lombok.NonNull;

import at.favre.lib.crypto.HKDF;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EndpointRole;
import com.timtrense.quic.impl.HkdfUtil;
import com.timtrense.quic.impl.PacketProtection;
import com.timtrense.quic.impl.packets.InitialPacketImpl;

@Data
public class InitialPacketProtectionImpl implements PacketProtection {

    /**
     * The initial salt is a meaningless truly random number defined by the protocol authors.
     *
     * @see <a href="https://github.com/quicwg/base-drafts/issues/4325">Github Issue of QUIC Working Group about the
     * arbitrary nature of that salt</a>
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final byte[] INITIAL_SALT_v1 = new byte[]{
            (byte) 0x38, (byte) 0x76, (byte) 0x2c, (byte) 0xf7, (byte) 0xf5, (byte) 0x59, (byte) 0x34, (byte) 0xb3, (byte) 0x4d, (byte) 0x17, (byte) 0x9a, (byte) 0xe6, (byte) 0xa4, (byte) 0xc8, (byte) 0x0c, (byte) 0xad, (byte) 0xcc, (byte) 0xbb, (byte) 0x7f, (byte) 0x0a

    };
    public static final byte[] handshake_salt_draft_23 = new byte[]{
            (byte) 0xc3, (byte) 0xee, (byte) 0xf7, (byte) 0x12, (byte) 0xc7, (byte) 0x2e, (byte) 0xbb, (byte) 0x5a, (byte) 0x11, (byte) 0xa7, (byte) 0xd2, (byte) 0x43, (byte) 0x2b, (byte) 0xb4, (byte) 0x63, (byte) 0x65, (byte) 0xbe, (byte) 0xf9, (byte) 0xf5, (byte) 0x02,
    };
    public static final byte[] handshake_salt_draft_22 = new byte[]{
            (byte) 0x7f, (byte) 0xbc, (byte) 0xdb, (byte) 0x0e, (byte) 0x7c, (byte) 0x66, (byte) 0xbb, (byte) 0xe9, (byte) 0x19, (byte) 0x3a,
            (byte) 0x96, (byte) 0xcd, (byte) 0x21, (byte) 0x51, (byte) 0x9e, (byte) 0xbd, (byte) 0x7a, (byte) 0x02, (byte) 0x64, (byte) 0x4a
    };
    public static final byte[] handshake_salt_draft_29 = new byte[]{
            (byte) 0xaf, (byte) 0xbf, (byte) 0xec, (byte) 0x28, (byte) 0x99, (byte) 0x93, (byte) 0xd2, (byte) 0x4c, (byte) 0x9e, (byte) 0x97,
            (byte) 0x86, (byte) 0xf1, (byte) 0x9c, (byte) 0x61, (byte) 0x11, (byte) 0xe0, (byte) 0x43, (byte) 0x90, (byte) 0xa8, (byte) 0x99
    };
    public static final byte[] hanshake_salt_draft_q50 = new byte[]{
            (byte) 0x50, (byte) 0x45, (byte) 0x74, (byte) 0xEF, (byte) 0xD0, (byte) 0x66, (byte) 0xFE, (byte) 0x2F, (byte) 0x9D, (byte) 0x94,
            (byte) 0x5C, (byte) 0xFC, (byte) 0xDB, (byte) 0xD3, (byte) 0xA7, (byte) 0xF0, (byte) 0xD3, (byte) 0xB5, (byte) 0x6B, (byte) 0x45
    };
    public static final byte[] hanshake_salt_draft_t50 = new byte[]{
            (byte) 0x7f, (byte) 0xf5, (byte) 0x79, (byte) 0xe5, (byte) 0xac, (byte) 0xd0, (byte) 0x72, (byte) 0x91, (byte) 0x55, (byte) 0x80,
            (byte) 0x30, (byte) 0x4c, (byte) 0x43, (byte) 0xa2, (byte) 0x36, (byte) 0x7c, (byte) 0x60, (byte) 0x48, (byte) 0x83, (byte) 0x10
    };
    public static final byte[] hanshake_salt_draft_t51 = new byte[]{
            (byte) 0x7a, (byte) 0x4e, (byte) 0xde, (byte) 0xf4, (byte) 0xe7, (byte) 0xcc, (byte) 0xee, (byte) 0x5f, (byte) 0xa4, (byte) 0x50,
            (byte) 0x6c, (byte) 0x19, (byte) 0x12, (byte) 0x4f, (byte) 0xc8, (byte) 0xcc, (byte) 0xda, (byte) 0x6e, (byte) 0x03, (byte) 0x3d
    };
    public static final byte[] handshake_salt_v2_draft_00 = new byte[]{
            (byte) 0xa7, (byte) 0x07, (byte) 0xc2, (byte) 0x03, (byte) 0xa5, (byte) 0x9b, (byte) 0x47, (byte) 0x18, (byte) 0x4a, (byte) 0x1d,
            (byte) 0x62, (byte) 0xca, (byte) 0x57, (byte) 0x04, (byte) 0x06, (byte) 0xea, (byte) 0x7a, (byte) 0xe3, (byte) 0xe5, (byte) 0xd3
    };
//,
    /**
     * The hash function for HKDF when deriving initial secrets and keys is SHA-256 [SHA].
     *
     * @see <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.2">QUIC Spec-TLS/Section 5.2</a>
     */
    public static final HKDF INITIAL_DERIVATION_FUNCTION = HKDF.fromHmacSha256();

    private @NonNull EndpointRole endpointRole;
    private byte[] clientInitialSecret;
    private byte[] serverInitialSecret;
    private byte[] clientInitialKey;
    private byte[] clientInitialIV;
    private byte[] headerProtectionSecret;
    private Cipher headerProtectionCipher;

    /**
     * Generates the initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param clientDestinationConnectionId the pseudo-code-parameter client_dst_connection_id
     * @param version
     * @return the pseudo-code-result initial_secret
     */
    public static byte[] extractInitialSecret(@NonNull ConnectionId clientDestinationConnectionId, ProtocolVersion version) {
        int drafted_version = version.getIetfDraftVersion();
        byte[] initialSecret;
        if (version.getValue() == 0x51303530)
            initialSecret = hanshake_salt_draft_q50;
        else if (version.getValue() == 0x54303531) {
            initialSecret = hanshake_salt_draft_t51;
        } else if (drafted_version <=22) {
            initialSecret = handshake_salt_draft_22;
        } else if (drafted_version <=28) {
            initialSecret = handshake_salt_draft_23;
        } else if (drafted_version <=32) {
            initialSecret = handshake_salt_draft_29;
        } else if (drafted_version <=34) {
            initialSecret = INITIAL_SALT_v1;
        } else {
            initialSecret = handshake_salt_v2_draft_00;
        }


        return INITIAL_DERIVATION_FUNCTION.extract(initialSecret, clientDestinationConnectionId.getValue());
    }

    /**
     * Generates the client_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result client_initial_secret
     */
    public static byte[] expandInitialClientSecret(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_CLIENT_IN /*"client in"*/, null, (256 / 8) /*sha 256 byte length*/);
    }

    /**
     * Generates the server_initial_secret as described by the pseudo-code of Section 5.2
     *
     * @param initialSecret the pseudo-code-parameter initial_secret
     * @return the pseudo-code-result server_initial_secret
     */
    public static byte[] expandInitialServerSecret(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_SERVER_IN, null, (256 / 8) /*sha 256 byte length*/);
    }

    public static byte[] expandInitialHeaderProtection(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_HP, null, 16 /* header protection mask byte length */);
    }

    public static byte[] expandInitialQuicKey(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_KEY, null, (128 / 8));
    }

    public static byte[] expandInitialQuicIv(@NonNull byte[] initialSecret) {
        return HkdfUtil.tlsExpandLabel(INITIAL_DERIVATION_FUNCTION,
                initialSecret, HkdfUtil.LABEL_QUIC_IV, null, (96 / 8));
    }

    /**
     * Computes all initial secrets for server, client and header protection
     *
     * @param clientDestinationConnectionId the destination connection id sent by the client
     *                                      in the {@link InitialPacketImpl}
     * @param protocolVersion
     * @throws NoSuchPaddingException   if the spec-required cipher could not be initialized
     * @throws NoSuchAlgorithmException if the spec-required cipher could not be initialized
     * @throws InvalidKeyException      if the spec-required cipher could not be initialized
     */

    public void initialize(@NonNull ConnectionId clientDestinationConnectionId, ProtocolVersion protocolVersion)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {


        byte[] initialSecret = extractInitialSecret(clientDestinationConnectionId, protocolVersion);
        clientInitialSecret = expandInitialClientSecret(initialSecret);
        serverInitialSecret = expandInitialServerSecret(initialSecret);
        clientInitialKey = expandInitialQuicKey(clientInitialSecret);
        clientInitialIV = expandInitialQuicIv(clientInitialSecret);
        headerProtectionSecret = expandInitialHeaderProtection(clientInitialSecret);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.3
        // "AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES [AES] in electronic code-book (ECB) mode."
        headerProtectionCipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(headerProtectionSecret, "AES");
        headerProtectionCipher.init(Cipher.ENCRYPT_MODE, keySpec);
    }

    @Override
    public byte[] deriveHeaderProtectionMask(@NonNull byte[] sample, int offset, int length) {
        if (headerProtectionCipher == null) {
            return null;
        }
        try {
            return headerProtectionCipher.doFinal(sample, offset, length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Derives the 16 bytes nonce used as a {@link GCMParameterSpec GCM Parameter} for AEAD_AES_128_GCM.
     * <p/>
     * "The nonce, N, is formed by combining the packet
     * protection IV with the packet number. The 62 bits of the
     * reconstructed QUIC packet number in network byte order are left-
     * padded with zeros to the size of the IV. The exclusive OR of the
     * padded packet number and the IV forms the AEAD nonce."
     * Quote from
     * <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5.3">QUIC Spec-TLS/Section 5.3</a>
     *
     * @param packetNumber the packet number to combine with the input vector
     * @return the nonce for AEAD_AES_128_GCM, never null, always 16 bytes length
     */
    public byte[] deriveAeadNonce(long packetNumber) {
        byte[] nonce = new byte[12]; // java arrays are prefilled with 0
        VariableLengthIntegerEncoder.encodeFixedLengthInteger(packetNumber, nonce, 4, 8);
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] ^= clientInitialIV[i];
        }
        return nonce;
    }

    /**
     * Performs AEAD_AES_128_GCM decryption using this {@link #clientInitialKey}.
     * <p/>
     * "Initial packets use AEAD_AES_128_GCM with keys derived from the
     * Destination Connection ID field of the first Initial packet sent
     * by the client; see Section 5.2."
     * Quote from
     * <a href="https://tools.ietf.org/html/draft-ietf-quic-tls-32#section-5">QUIC Spec-TLS/Section 5</a>
     * <p>
     * Hint: all exceptions thrown by this method are of subtypes of {@link GeneralSecurityException}
     *
     * @param message        the ciphertext to decrypt
     * @param associatedData the associated data (in QUIC: the unprotected packet header including the unprotected
     *                       packet number)
     * @param nonce          the nonce derived from the packet number (see {@link #deriveAeadNonce(long)})
     * @return the decrypted ciphertext, thus the plaintext of the message
     * @throws BadPaddingException                if decryption somehow fails
     * @throws NoSuchPaddingException             if decryption somehow fails
     * @throws IllegalBlockSizeException          if decryption somehow fails
     * @throws InvalidAlgorithmParameterException if decryption somehow fails
     * @throws InvalidKeyException                if decryption somehow fails
     * @throws NoSuchAlgorithmException           if decryption somehow fails
     */
    public byte[] aeadDecrypt(byte[] message, byte[] associatedData, byte[] nonce)
            throws BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher aeadCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(clientInitialKey, "AES");

        GCMParameterSpec parameterSpec = new GCMParameterSpec(128 /* AEAD_AES_128_GCM */, nonce);

        aeadCipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        aeadCipher.updateAAD(associatedData);
        return aeadCipher.doFinal(message);
    }

}
