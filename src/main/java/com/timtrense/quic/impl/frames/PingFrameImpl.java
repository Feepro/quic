package com.timtrense.quic.impl.frames;

import com.timtrense.quic.Frame;
import com.timtrense.quic.FrameType;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

public class PingFrameImpl implements Frame {
    @Getter
    private int length;

    /**
     * Creates a new combination of <code>length</code> {@link PaddingFrameImpl}
     *
     * @param length how many padding frames to represent by this instance, must be positive
     */
    public PingFrameImpl( int length ) {
        setLength( 1 );
    }

    /**
     * Creates a new instance that represents exactly ONE {@link PaddingFrameImpl}.
     * <p/>
     * <b>Hint:</b><br/>
     * Users should use <code>new PaddingFrameImpl(FrameType.PADDING)</code> directly
     * instead of creating a useless MULTI-PaddingFrameImpl if they wish to represent
     * exactly one padding frame. Instantiation of this class is fine if the true
     * length of consecutive padding frames will only after instantiation happens be
     * known. Nevertheless it is perfectly valid to have a multi padding frame of
     * length 1.
     */
    public PingFrameImpl() {
        this( 1 );
    }

    @Override
    public FrameType getType() {
        return FrameType.PING;
    }

    public void setLength( int length ) {
        if ( length < 0 ) {
            throw new IllegalArgumentException( "Cannot have a multi padding frame with non-positive length" );
        }
        this.length = length;
    }

    @Override
    public boolean isValid() {
        return true;
    }

    /**
     * The returned length does NOT specify ONE frame, but instead is the combined
     * length of all (one-byte-length) {@link PaddingFrameImpl} combined within this instance
     *
     * @return the number of bytes padded, always positive
     */
    @Override
    public long getFrameLength() {
        return length;
    }
}

