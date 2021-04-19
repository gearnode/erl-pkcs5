%% Copyright (c) 2020, 2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(pkcs5).

-export([pbkdf2/4, pbkdf2/5,
         secure_compare/2]).

pbkdf2(Digest, Password, Salt, IterationCount) ->
  pkcs5_pbkdf2:pbkdf2(Digest, Password, Salt, IterationCount).

pbkdf2(Digest, Password, Salt, IterationCount, DKLen) ->
  pkcs5_pbkdf2:pbkdf2(Digest, Password, Salt, IterationCount, DKLen).

-spec secure_compare(binary(), binary()) ->
        boolean().
secure_compare(A, B) when is_binary(A), is_binary(B) ->
  case byte_size(A) =:= byte_size(B) of
    true -> secure_compare(A, B, 0);
    false -> false
  end.

-spec secure_compare(binary(), binary(), integer()) ->
        boolean().
secure_compare(<<>>, <<>>, Result) ->
  Result =:= 0;
secure_compare(<<A, RestA/binary>>, <<B, RestB/binary>>, Result) ->
  secure_compare(RestA, RestB, (A bxor B) bor Result).
