package com.timtrense.quic.impl;

import java.nio.ByteBuffer;

import org.junit.BeforeClass;
import org.junit.Test;

import com.timtrense.quic.ConnectionId;
import com.timtrense.quic.EndpointRole;
import com.timtrense.quic.Frame;
import com.timtrense.quic.HexByteStringConvertHelper;
import com.timtrense.quic.Packet;
import com.timtrense.quic.ProtocolVersion;
import com.timtrense.quic.VariableLengthInteger;
import com.timtrense.quic.impl.base.ConnectionIdImpl;
import com.timtrense.quic.impl.base.PacketNumberImpl;
import com.timtrense.quic.impl.exception.QuicParsingException;
import com.timtrense.quic.impl.frames.CryptoFrameImpl;
import com.timtrense.quic.impl.frames.MultiPaddingFrameImpl;
import com.timtrense.quic.impl.packets.InitialPacketImpl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @see com.timtrense.quic.impl.PacketParserImpl
 */
public class PacketParserImplTest {

    private static byte[] protectedInitialPacket;
    static ConnectionId expectedDestinationConnectionId;
//
//    @BeforeClass
//    public static void setupClientConnectionId() {
//        byte[] ccid = new byte[]{
//                (byte)0xf3, (byte)0x87, (byte)0x07, (byte)0xe5,
//                (byte)0xa2, (byte)0x35, (byte)0xe9, (byte)0x70
//        };
//        expectedDestinationConnectionId = new ConnectionIdImpl( ccid, VariableLengthInteger.ZERO );
//    }

    @BeforeClass
    public static void prepareProtectedIntialPacket() {

    }

    @Test
    public void parsePacket_GivenAppendixAContent_givesInitialPacket() {
        String hexdumpFromAppendixA = "cd0000000108c0a0fac6180666d900404600b593b651b48a6d581a5afeb621149a900a0b3087e6cf0c970f48e52dc67ebe0fa64d083f4d715413091fb9a5d014c35ed2a892b21813584bd69792d53ae775d00875939f86448915df7d679616eb12e02a75197ebf599d810ccecb2b91079fdc9269c0723d14e8ca0c3c5af0a72ffae43f5a0c764f3ed07b76423bef6c7b1581839a34a96827fcfb07fa4d59797b6af733ec233b38008a73e37856b3738797881fd0c430970ca65b0cdfff1c8707b61ccedeb8159bd122aa85f6c44c9dd41037952ba09b4d5a21293882ee2fb8117f6bf2584dc9cccfd33adc80f5addbbf36da71d33c4c6a3c0824469df14765331283a5b3b2fb346097ad2a84137cf0ba23266bb432a12ad49c93d9526e7e6939e40402aedc35620416b8207a307392edc3fc8b2f44427a3baae1b02a25496760cefb35b490a91c4efd92a0e7d613b586bb268cd82f46350f9eac6c09750812c610c30db4311421eb91d8e87fa1dfc5c09a104da0395979be9440fb37077309164a777a423065059c83977c4f642e48f34c2339863b8e56f3a4ddc7972a94991b8a5bf801941ea96007983b14c6a966a89a895571941fb6afe0c26992a4b551cccc6baef48fda8e9399f02c293485a0a4a8afc2b9ae60fd204e66e69855e478da5d4fd22715d9c6f77a51b887eabc16e45d529fc691ab288889ff923f95a475cb743bef92a46f9bfb2316993d19545050823f09b53fb89de1d220b733d958b58173ec8bce634fd59af6220b1ef27eb9ea2247e01866127f048d92abe8c47acf8116e9fc20063b781122e4f6d8d0573098a5a137abd9dff941ad80632d39b8877f0d85105dadb8fc097a4bdb3c0f224b8f440f4b53c525c18699b2ef045a6012a763a9fc6d1bf696094b0f8fe5fd87be10f93abf54ce599661eb5affab4979b07f096d8d0558086349d09d248ed461f9b7fc3a1dedc8765a5c7317ef5deab054ef9ec48ef87fc492b4c5046fe25f761cb695aedbad16f898b36b074410a31c4b09abfefc145e9a0470dbdcd199bf320598511a889da0c3899fb8de08946e5dd71f4b9cb45ec5dba5c1887466c6e87c1a15f1521214d994226087fbd95b0669e0ad889c331eaed6783eef44f6dae3e3ab3d24fe413724457f1d2dc62d31452955896bc04cf4cffa33f00ba3b6a6648becc44dcb1ef87dfbe1c159792de1bb90aa867b179a6bc71a0d7f259741eced62bad6f4c55ae0c610d0bab6b13933cb71b8c2949634aced7372d743650131d5d6221526908edc41b3d08c8ae32f69ff2d320fd808e60e073f18fac40272fb45c6ccb9cb4363670380407c47b5b361e06a21059c5ecb2f0081eecb1fd6109ddc2456ac8e424b509ae4418c34aecd0a26e6fa328f5ea4996ddaf82845dffc0e59712a1c8d197d9d5219a8730f6dffbc4c345f0dae4bc140bf5f4f4d2190c1a30fd06374361468672e3209815fb39f87d763b3c4610658931f1f47ba305e69ca42b86c92f960a8f61d72b5500119415a58c06407c38c068fce027ea71c33249a3ac2a2b5f1d971101f532e1798c771aaeead692ae6284a5af2f7cb55a26a0fecf4ef3b20e0be05076b7fec84d9f7b2c69c497dbe449e6a565862fd1839c092055d5b2bf624e1cdaf1b3794f9dfdbb39bb92f57eef2943ace0746b7dfcbb9a59ef90ec96f5a2f98782b71022a9290ef68cebbbe52f7817a055ebd3690de2978de2aad33ae6aa9776998a0cd003b93851953e113d0b0bf";
        hexdumpFromAppendixA = hexdumpFromAppendixA.replaceAll( " ", "" );
        protectedInitialPacket = HexByteStringConvertHelper.hexStringToByteArray( hexdumpFromAppendixA );

        Endpoint endpoint = new Endpoint( EndpointRole.SERVER );
        PacketParser packetParser = new PacketParserImpl( endpoint );
        ByteBuffer packetData = ByteBuffer.wrap( protectedInitialPacket );

        Packet packet = null;
        try {
            packet = packetParser.parsePacket( null, packetData, 0 );
        }
        catch ( QuicParsingException e ) {
            e.printStackTrace();
        }

        InitialPacketImpl initialPacket = (InitialPacketImpl)packet;
//        assertEquals( (byte)0xc3, initialPacket.getFlags() );
//        assertEquals( ProtocolVersion.ONE, initialPacket.getVersion() );
//        assertEquals( 8L, initialPacket.getDestinationConnectionIdLength() );
//        assertEquals( 0L, initialPacket.getSourceConnectionIdLength() );
//        assertArrayEquals( new byte[]{(byte)0x83, (byte)0x94, (byte)0xc8, (byte)0xf0,
//                (byte)0x3e, (byte)0x51, (byte)0x57, (byte)0x08}, initialPacket.getDestinationConnectionId().getValue() );
//        assertEquals( VariableLengthInteger.ZERO, initialPacket.getDestinationConnectionId().getSequenceNumber() );
//        assertArrayEquals( new byte[]{}, initialPacket.getSourceConnectionId().getValue() );
//        assertEquals( VariableLengthInteger.ZERO, initialPacket.getSourceConnectionId().getSequenceNumber() );
//        assertEquals( VariableLengthInteger.ZERO, initialPacket.getTokenLength() );
//        assertArrayEquals( null, initialPacket.getToken() );
//        assertEquals( new PacketNumberImpl( 2 ), initialPacket.getPacketNumber() );
//
//        assertNotNull( initialPacket.getPayload() );
//        assertFalse( initialPacket.getPayload().isEmpty() );
//        assertEquals( 2, initialPacket.getPayload().size() );
//
//        Frame firstFrame = initialPacket.getPayload().get( 0 );
//        Frame secondFrame = initialPacket.getPayload().get( 1 );
//        assertTrue( firstFrame instanceof CryptoFrameImpl );
//        assertTrue( secondFrame instanceof MultiPaddingFrameImpl );
    }

}
