%% Copyright (c) 2020 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
%% REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
%% AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
%% INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
%% LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
%% OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
%% PERFORMANCE OF THIS SOFTWARE.

-module(pkcs_base16_tests).

-include_lib("eunit/include/eunit.hrl").

encode16_test_() ->
    [?_assertEqual(<<>>, pkcs_base16:encode(<<>>)),
     ?_assertEqual(<<"66">>, pkcs_base16:encode(<<"f">>)),
     ?_assertEqual(<<"666f">>, pkcs_base16:encode(<<"fo">>)),
     ?_assertEqual(<<"666f6f">>, pkcs_base16:encode(<<"foo">>)),
     ?_assertEqual(<<"666f6f62">>, pkcs_base16:encode(<<"foob">>)),
     ?_assertEqual(<<"666f6f6261">>, pkcs_base16:encode(<<"fooba">>)),
     ?_assertEqual(<<"666f6f626172">>, pkcs_base16:encode(<<"foobar">>))].
