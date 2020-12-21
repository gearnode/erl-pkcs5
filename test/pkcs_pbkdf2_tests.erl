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

pbkdf2_b16(Digest, Password, Salt, IC) ->
    {ok, Result} = pkcs_pbkdf2:pbkdf2(Digest, Password, Salt, IC),
    pkcs_base16:encode(Result).

pbkdf2_b16(Digest, Password, Salt, IC, KLen) ->
    {ok, Result} = pkcs_pbkdf2:pbkdf2(Digest, Password, Salt, IC, KLen),
    pkcs_base16:encode(Result).

pbkdf2_short_func_test_() ->
    [?_assertEqual(<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>,
                   pbkdf2_b16(sha, <<"password">>, <<"salt">>, 1))].

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

rfc3962_test_() ->
    [?_assertEqual(<<"cdedb5281bb2f801565a1122b2563515">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1, 16)),
     ?_assertEqual(<<"cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1, 32)),
     ?_assertEqual(<<"01dbee7f4a9e243e988b62c73cda935d">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 2, 16)),
     ?_assertEqual(<<"01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 2, 32)),
     ?_assertEqual(<<"5c08eb61fdf71e4e4ec3cf6ba1f5512b">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1200, 16)),
     ?_assertEqual(<<"5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13">>,
                   pbkdf2_b16(sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1200, 32)),
     ?_assertEqual(<<"d1daa78615f287e6a1c8b120d7062a49">>,
                   pbkdf2_b16(sha, <<"password">>, binary:encode_unsigned(16#1234567878563412), 5, 16)),
     ?_assertEqual(<<"d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee">>,
                   pbkdf2_b16(sha, <<"password">>, binary:encode_unsigned(16#1234567878563412), 5, 32)),
     ?_assertEqual(<<"139c30c0966bc32ba55fdbf212530ac9">>,
                   pbkdf2_b16(sha,
                              <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
                              <<"pass phrase equals block size">>,
                              1200, 16)),
     ?_assertEqual(<<"139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1">>,
                   pbkdf2_b16(sha,
                              <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
                              <<"pass phrase equals block size">>,
                              1200, 32)),
     ?_assertEqual(<<"9ccad6d468770cd51b10e6a68721be61">>,
                   pbkdf2_b16(sha,
                              <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
                              <<"pass phrase exceeds block size">>,
                              1200, 16)),
     ?_assertEqual(<<"9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a">>,
                   pbkdf2_b16(sha,
                              <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
                              <<"pass phrase exceeds block size">>,
                              1200, 32)),
     ?_assertEqual(<<"6b9cf26d45455a43a5b8bb276a403b39">>,
                   pbkdf2_b16(sha, binary:encode_unsigned(16#f09d849e), <<"EXAMPLE.COMpianist">>, 50, 16)),
     ?_assertEqual(<<"6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52">>,
                   pbkdf2_b16(sha, binary:encode_unsigned(16#f09d849e), <<"EXAMPLE.COMpianist">>, 50, 32))].
