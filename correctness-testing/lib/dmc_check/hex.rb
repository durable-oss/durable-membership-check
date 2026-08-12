# frozen_string_literal: true

module DmcCheck
  # Hex encoding for the CLI boundary.
  #
  # Keys are arbitrary bytes; JSON strings are Unicode. Every key crosses as
  # hex so that a key containing a NUL, a lone 0xFF, or an invalid UTF-8
  # sequence arrives unchanged. Those keys are precisely the ones worth testing.
  module Hex
    # Encodes a byte string as lowercase hex.
    #
    # @param bytes [String]
    # @return [String]
    def self.encode(bytes)
      bytes.b.unpack1("H*")
    end

    # Encodes many byte strings.
    #
    # @param list [Array<String>]
    # @return [Array<String>]
    def self.encode_all(list)
      list.map { |bytes| encode(bytes) }
    end

    # Decodes hex into a byte string.
    #
    # Always returns ASCII-8BIT, so a decoded key compares equal to the byte
    # string it was made from rather than differing by encoding alone.
    #
    # @param text [String]
    # @return [String]
    def self.decode(text)
      [text].pack("H*").b
    end
  end
end
