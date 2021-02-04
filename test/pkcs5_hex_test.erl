%% Copyright (c) 2020 Bryan Frimin <bryan@frimin.fr>.
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

-module(pkcs5_hex_test).

-include_lib("eunit/include/eunit.hrl").

-export([encode/1]).

-spec encode(binary()) -> binary().
encode(Bin) ->
  encode(Bin, <<>>).

-spec encode(binary(), binary()) -> binary().
encode(<<>>, Acc) ->
  Acc;
encode(<<A:4, B:4, Rest/binary>>, Acc) ->
  encode(Rest, <<Acc/binary, (enc16(A)), (enc16(B))>>).

-spec enc16(0..15) -> byte().
enc16(Char) when Char =< 9 ->
  Char + $0;
enc16(Char) when Char =< 15 ->
  Char + $a - 10.

encode16_test_() ->
  [?_assertEqual(<<>>, encode(<<>>)),
   ?_assertEqual(<<"66">>, encode(<<"f">>)),
   ?_assertEqual(<<"666f">>, encode(<<"fo">>)),
   ?_assertEqual(<<"666f6f">>, encode(<<"foo">>)),
   ?_assertEqual(<<"666f6f62">>, encode(<<"foob">>)),
   ?_assertEqual(<<"666f6f6261">>, encode(<<"fooba">>)),
   ?_assertEqual(<<"666f6f626172">>, encode(<<"foobar">>))].
