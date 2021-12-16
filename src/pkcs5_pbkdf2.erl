%% Copyright (c) 2020, 2021 Exograd SAS.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
%% SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
%% IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(pkcs5_pbkdf2).

-export([pbkdf2/4, pbkdf2/5]).

-export_type([password/0,
              salt/0,
              ic/0,
              dk_len/0,
              dk/0,
              digest/0]).

-type password() :: binary().
-type salt() :: binary().
-type ic() :: pos_integer().
-type dk_len() :: pos_integer().
-type dk() :: binary().
-type digest() ::
        sha
      | sha224
      | sha256
      | sha384
      | sha512
      | sha3_224
      | sha3_256
      | sha3_384
      | sha3_512
      | md5
      | md4.

-spec pbkdf2(digest(), password(), salt(), ic()) ->
        {ok, dk()} | {error, term()}.
pbkdf2(Digest, Password, Salt, IterationCount) ->
  DKLen = byte_size(crypto:mac(hmac, Digest, <<>>, <<>>)),
  pbkdf2(Digest, Password, Salt, IterationCount, DKLen).

-spec pbkdf2(digest(), password(), salt(), ic(), dk_len()) ->
        {ok, dk()} | {error, term()}.
pbkdf2(_Digest, _Password, _Salt, _IterationCount, DKLen) when DKLen < 0 ->
  {error, derived_key_too_short};
pbkdf2(_Digest, _Password, _Salt, IterationCount, _DKLen)
  when IterationCount < 0 ->
  {error, iteration_count_too_short};
pbkdf2(Digest, Password, Salt, IterationCount, DKLen) ->
  HLen = byte_size(crypto:mac(hmac, Digest, Salt, Password)),
  case DKLen > ((1 bsl 32) - 1) * HLen of
    true ->
      {error, derived_key_too_long};
    false ->
      BlockNedeed = round(math:ceil(DKLen / HLen)),
      LastBlockSize = DKLen - (BlockNedeed - 1) * HLen,
      Data = compute(Digest, Password, Salt, IterationCount, BlockNedeed,
                     LastBlockSize, 1, <<>>),
      {ok, <<Data:DKLen/binary>>}
  end.

-spec compute(digest(), password(), salt(), ic(), pos_integer(),
              non_neg_integer(), pos_integer(), binary()) ->
        binary().
compute(Digest, Password, Salt, IterationCount, BlockNedeed, LastBlockSize,
        BlockIndex, Acc)
  when BlockIndex =:= BlockNedeed ->
  Block0 = compute_block(Digest, Password, Salt, IterationCount, BlockIndex,
                         1, <<>>, <<>>),
  Block = <<Block0:LastBlockSize/binary>>,
  <<Acc/binary, Block/binary>>;
compute(Digest, Password, Salt, IterationCount, BlockNedeed, LastBlockSize,
        BlockIndex, Acc) ->
  Block = compute_block(Digest, Password, Salt, IterationCount, BlockIndex,
                        1, <<>>, <<>>),
  compute(Digest, Password, Salt, IterationCount, BlockNedeed, LastBlockSize,
          BlockIndex + 1, <<Acc/binary, Block/binary>>).

-spec compute_block(digest(), password(), salt(), ic(), pos_integer(),
                    pos_integer(), binary(), binary()) ->
        binary().
compute_block(_Digest, _Password, _Salt, IterationCount, _BlockIndex,
              Iteration, _Prev, Acc) when Iteration > IterationCount ->
  Acc;
compute_block(Digest, Password, Salt, IterationCount, BlockIndex, 1,
              _Prev, _Acc) ->
  InitialBlock = crypto:mac(hmac, Digest, Password,
                            <<Salt/binary, BlockIndex:32>>),
  compute_block(Digest, Password, Salt, IterationCount, BlockIndex, 2,
                InitialBlock, InitialBlock);
compute_block(Digest, Password, Salt, IterationCount, BlockIndex, Iteration,
              Prev, Acc) ->
  NextBlock = crypto:mac(hmac, Digest, Password, Prev),
  compute_block(Digest, Password, Salt, IterationCount, BlockIndex,
                Iteration + 1, NextBlock, crypto:exor(NextBlock, Acc)).
