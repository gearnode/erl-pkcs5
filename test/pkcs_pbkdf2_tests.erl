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

-module(pkcs_pbkdf2_tests).

-include_lib("eunit/include/eunit.hrl").

pbkdf2_b16(Digest, Password, Salt, IC, KLen) ->
    {ok, Result} = pkcs_pbkdf2:pbkdf2(Digest, Password, Salt, IC, KLen),
    pkcs_base16:encode(Result).

rfc6070_test_() ->
     [?_assertEqual(<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>,
                    pbkdf2_b16(sha, <<"password">>, <<"salt">>, 1, 20)),
      ?_assertEqual(<<"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957">>,
                    pbkdf2_b16(sha, <<"password">>, <<"salt">>, 2, 20)),
      ?_assertEqual(<<"4b007901b765489abead49d926f721d065a429c1">>,
                    pbkdf2_b16(sha, <<"password">>, <<"salt">>, 4096, 20)),
      {timeout, 60, ?_assertEqual(<<"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984">>,
                                     pbkdf2_b16(sha, <<"password">>, <<"salt">>, 16777216, 20))},
      ?_assertEqual(<<"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038">>,
                    pbkdf2_b16(sha, <<"passwordPASSWORDpassword">>, <<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>, 4096, 25)),
      ?_assertEqual(<<"56fa6aa75548099dcc37d7f03425e0c3">>,
                    pbkdf2_b16(sha, <<"pass\0word">>, <<"sa\0lt">>, 4096, 16))].
