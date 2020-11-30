package com.timtrense.quic.tls.extensions;

import lombok.Data;
import lombok.EqualsAndHashCode;

import com.timtrense.quic.tls.Extension;
import com.timtrense.quic.tls.ExtensionType;
import com.timtrense.quic.tls.handshake.NewSessionTicket;

/**
 * When a PSK is used and early data is allowed for that PSK, the client
 * can send Application Data in its first flight of messages.  If the
 * client opts to do so, it MUST supply both the "pre_shared_key" and
 * "early_data" extensions.
 * <p/>
 * The "extension_data" field of this extension contains an
 * "EarlyDataIndication" value.
 * <pre>
 * struct {} Empty;
 *
 * struct {
 *     select (Handshake.msg_type) {
 *         case new_session_ticket:   uint32 max_early_data_size;
 *         case client_hello:         Empty;
 *         case encrypted_extensions: Empty;
 *     };
 * } EarlyDataIndication;
 * </pre>
 * <p/>
 * See Section 4.6.1 for details regarding the use of the
 * max_early_data_size field.
 * <p/>
 * The parameters for the 0-RTT data (version, symmetric cipher suite,
 * Application-Layer Protocol Negotiation (ALPN) [RFC7301] protocol,
 * etc.) are those associated with the PSK in use.  For externally
 * provisioned PSKs, the associated values are those provisioned along
 * with the key.  For PSKs established via a NewSessionTicket message,
 * the associated values are those which were negotiated in the
 * connection which established the PSK.  The PSK used to encrypt the
 * early data MUST be the first PSK listed in the client's
 * "pre_shared_key" extension.
 * <p/>
 * For PSKs provisioned via NewSessionTicket, a server MUST validate
 * that the ticket age for the selected PSK identity (computed by
 * subtracting ticket_age_add from PskIdentity.obfuscated_ticket_age
 * modulo 2^32) is within a small tolerance of the time since the ticket
 * was issued (see Section 8).  If it is not, the server SHOULD proceed
 * with the handshake but reject 0-RTT, and SHOULD NOT take any other
 * action that assumes that this ClientHello is fresh.
 * <p/>
 * 0-RTT messages sent in the first flight have the same (encrypted)
 * content types as messages of the same type sent in other flights
 * (handshake and application_data) but are protected under different
 * keys.  After receiving the server's Finished message, if the server
 * has accepted early data, an EndOfEarlyData message will be sent to
 * indicate the key change.  This message will be encrypted with the
 * 0-RTT traffic keys.
 * <p/>
 * A server which receives an "early_data" extension MUST behave in one
 * of three ways:
 * <ul>
 *     <li>
 *     Ignore the extension and return a regular 1-RTT response.  The
 *       server then skips past early data by attempting to deprotect
 *       received records using the handshake traffic key, discarding
 *       records which fail deprotection (up to the configured
 *       max_early_data_size).  Once a record is deprotected successfully,
 *       it is treated as the start of the client's second flight and the
 *       server proceeds as with an ordinary 1-RTT handshake.
 *     </li>
 *     <li>
 *     Request that the client send another ClientHello by responding
 *       with a HelloRetryRequest.  A client MUST NOT include the
 *       "early_data" extension in its followup ClientHello.  The server
 *       then ignores early data by skipping all records with an external
 *       content type of "application_data" (indicating that they are
 *       encrypted), up to the configured max_early_data_size.
 *     </li>
 *     <li>
 *     Return its own "early_data" extension in EncryptedExtensions,
 *       indicating that it intends to process the early data.  It is not
 *       possible for the server to accept only a subset of the early data
 *       messages.  Even though the server sends a message accepting early
 *       data, the actual early data itself may already be in flight by the
 *       time the server generates this message.
 *     </li>
 * </ul>
 * <p/>
 * In order to accept early data, the server MUST have accepted a PSK
 * cipher suite and selected the first key offered in the client's
 * "pre_shared_key" extension.  In addition, it MUST verify that the
 * following values are the same as those associated with the
 * selected PSK:
 * <ul>
 *     <li>
 *         The TLS version number
 *     </li>
 *     <li>
 *         The selected cipher suite
 *     </li>
 *     <li>
 *         The selected ALPN [RFC7301] protocol, if any
 *     </li>
 * </ul>
 * <p/>
 * These requirements are a superset of those needed to perform a 1-RTT
 * handshake using the PSK in question.  For externally established
 * PSKs, the associated values are those provisioned along with the key.
 * For PSKs established via a NewSessionTicket message, the associated
 * values are those negotiated in the connection during which the ticket
 * was established.
 * <p/>
 * <b>Future extensions MUST define their interaction with 0-RTT.</b>
 * <p/>
 * If any of these checks fail, the server MUST NOT respond with the
 * extension and must discard all the first-flight data using one of the
 * first two mechanisms listed above (thus falling back to 1-RTT or
 * 2-RTT).  If the client attempts a 0-RTT handshake but the server
 * rejects it, the server will generally not have the 0-RTT record
 * protection keys and must instead use trial decryption (either with
 * the 1-RTT handshake keys or by looking for a cleartext ClientHello in
 * the case of a HelloRetryRequest) to find the first non-0-RTT message.
 * <p/>
 * If the server chooses to accept the "early_data" extension, then it
 * MUST comply with the same error-handling requirements specified for
 * all records when processing early data records.  Specifically, if the
 * server fails to decrypt a 0-RTT record following an accepted
 * "early_data" extension, it MUST terminate the connection with a
 * "bad_record_mac" alert as per Section 5.2.
 * <p/>
 * If the server rejects the "early_data" extension, the client
 * application MAY opt to retransmit the Application Data previously
 * sent in early data once the handshake has been completed.  Note that
 * automatic retransmission of early data could result in incorrect
 * assumptions regarding the status of the connection.  For instance,
 * when the negotiated connection selects a different ALPN protocol from
 * what was used for the early data, an application might need to
 * construct different messages.  Similarly, if early data assumes
 * anything about the connection state, it might be sent in error after
 * the handshake completes.
 * <p/>
 * A TLS implementation SHOULD NOT automatically resend early data;
 * applications are in a better position to decide when retransmission
 * is appropriate.  A TLS implementation MUST NOT automatically resend
 * early data unless the negotiated connection selects the same ALPN
 * protocol.
 *
 * @author Tim Trense
 * @see <a href="https://tools.ietf.org/html/rfc8446#section-4.2.10">TLS 1.3 Spec/Section 4.2.10</a>
 */
@Data
@EqualsAndHashCode( callSuper = true )
public class EarlyDataIndicationExtension extends Extension {

    /**
     * uint32
     * <p/>
     * <b>If applied in {@link NewSessionTicket}</b>
     * The maximum amount of 0-RTT data that the
     * client is allowed to send when using this ticket, in bytes.  Only
     * Application Data payload (i.e., plaintext but not padding or the
     * inner content type byte) is counted.  A server receiving more than
     * max_early_data_size bytes of 0-RTT data SHOULD terminate the
     * connection with an "unexpected_message" alert.  Note that servers
     * that reject early data due to lack of cryptographic material will
     * be unable to differentiate padding from content, so clients
     * SHOULD NOT depend on being able to send large quantities of
     * padding in early data records.
     * <p/>
     */
    private long maxEarlyDataSize;

    @Override
    public ExtensionType getExtensionType() {
        return ExtensionType.EARLY_DATA;
    }
}
