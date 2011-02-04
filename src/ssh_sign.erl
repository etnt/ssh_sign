%%%-------------------------------------------------------------------
%%% Created :  7 Dec 2010 by Torbjorn Tornkvist <tobbe@tornkvist.org>
%%%
%%% @doc Do Sign and Verify of data, making use of the users SSH keys.
%%%      This code is just enabling some missing functionality in the
%%%      R1304 ssh app.
%%% @end
%%%-------------------------------------------------------------------
-module(ssh_sign).

-include_lib("ssh.hrl").
-include_lib("PKCS-1.hrl").
-include_lib("DSS.hrl").

-export([sign/1
         ,sign/2
         ,verify/2
         ,verify/3
         ,public_identity_key/2
         ,private_identity_key/3
         ,read_public_key_v2/2
         ,foldf/3
         ,digest/5
         ,mk_term/4
         ,now_ish/0
        ]).


sign(Data) ->
    sign(Data, no_passwd).

sign(Data, Password) when is_binary(Data) ->
    {ok,{_,Type,_,_,_}=Key} =
        foldf(fun(T)->
                      private_identity_key(T,[], Password)
              end,
              fun({error,_}=Res)->Res;
                 (_)->true
              end,
              ["ssh-rsa", "ssh-dss"]),
    case Type of
        dsa -> ssh_dsa:sign(Key, Data);
        rsa -> ssh_rsa:sign(Key, Data)
    end.

verify(Data, Sig) when is_binary(Data), is_binary(Sig) ->
    {ok,Key} = public_identity_key("ssh-rsa",[]),
    ssh_rsa:verify(Key, Data, Sig).

verify(Data, Sig, Filename) ->
    ok.

public_identity_key(Alg, Opts) ->
    Path = ssh_file:file_name(user, public_identity_key_filename(Alg), Opts),
    read_public_key_v2(Path, Alg).

public_identity_key_filename("ssh-dss") -> "id_dsa.pub";
public_identity_key_filename("ssh-rsa") -> "id_rsa.pub".

read_public_key_v2(File, Type) ->
    case file:read_file(File) of
        {ok,Bin} ->
            List = binary_to_list(Bin),
            case lists:prefix(Type, List) of
                true ->
                    List1 = lists:nthtail(length(Type), List),
                    K_S = ssh_bits:b64_decode(List1),
                    ssh_file:decode_public_key_v2(K_S, Type);
                false ->
                    {error, bad_format}
            end;
        Error ->
            Error
    end.

identity_key_filename("ssh-dss") -> "id_dsa";
identity_key_filename("ssh-rsa") -> "id_rsa".

private_identity_key(Alg, Opts, Password) ->
    Path = ssh_file:file_name(user, identity_key_filename(Alg), Opts),
    read_private_key_v2(Path, Alg, Password).


read_private_key_v2(File, Type, Password) ->
     case catch (public_key:pem_to_der(File, Password)) of
	 {ok, [{_, Bin, _}]} ->
	     decode_private_key_v2(Bin, Type);
	 Error -> %% Note we do handle password encrypted keys at the moment
	     {error, Error}
     end.

decode_private_key_v2(Private,"ssh-rsa") ->
    case 'PKCS-1':decode( 'RSAPrivateKey', Private) of
	{ok,RSA} -> %% FIXME Check for two-prime version
	    {ok, #ssh_key { type = rsa,
			    public = {RSA#'RSAPrivateKey'.modulus,
				      RSA#'RSAPrivateKey'.publicExponent},
			    private = {RSA#'RSAPrivateKey'.modulus,
				       RSA#'RSAPrivateKey'.privateExponent}
			    }};
	Error ->
	    Error
    end;
decode_private_key_v2(Private, "ssh-dss") ->
    case 'DSS':decode('DSAPrivateKey', Private) of
	{ok,DSA} -> %% FIXME Check for two-prime version
	    {ok, #ssh_key { type = dsa,
			    public = {DSA#'DSAPrivateKey'.p,
				      DSA#'DSAPrivateKey'.q,
				      DSA#'DSAPrivateKey'.g,
				      DSA#'DSAPrivateKey'.y},
			    private= {DSA#'DSAPrivateKey'.p,
				      DSA#'DSAPrivateKey'.q,
				      DSA#'DSAPrivateKey'.g,
				      DSA#'DSAPrivateKey'.x}
			   }};
	_ ->
	    {error,bad_format}
    end.

digest(Passwd,A,B,C,Timestamp) ->
    {Timestamp, sign(mk_term(A,B,C,Timestamp),Passwd)}.

mk_term(A,B,C,Timestamp) ->
    term_to_binary({A,B,C,Timestamp}).

now_ish() ->
    {Msec, Sec, _} = now(),
    Msec*1000000 + Sec.

%% ----------------------------------------------------------------------------
%% @spec  foldf(fun(), fun(), list()) -> term()
%% @doc Runs the first fun on elements in the list.
%%      Returns the first result for which the predicate is true
%% @end------------------------------------------------------------------------

foldf(F, Pred, L) ->
    foldf(F, Pred, L, []).

foldf(F, Pred, [H|T], Acc) ->
    Res = F(H),
    case Pred(Res) of
        true -> Res;
        _    -> foldf(F, Pred, T, [Res|Acc])
    end;
foldf(_,_,[],Acc) -> {error, Acc}.
