%%%-------------------------------------------------------------------
%%% Created :  7 Dec 2010 by Torbjorn Tornkvist <tobbe@tornkvist.org>
%%%
%%% @doc Do Sign and Verify of data, making use of the users SSH keys.
%%%      This code is just enabling some missing functionality in the 
%%%      R1304 ssh app.
%%% @end
%%%-------------------------------------------------------------------
-module(ssh_sign).

-export([sign/1
         ,verify/2
         ,public_identity_key/2
         ,foldf/3
        ]).


sign(Data) when is_binary(Data) ->
    {ok,Key} = ssh_file:private_identity_key("ssh-rsa",[]),
    ssh_rsa:sign(Key, Data).

verify(Data, Sig) when is_binary(Data), is_binary(Sig) ->
    {ok,Key} = public_identity_key("ssh-rsa",[]),
    ssh_rsa:verify(Key, Data, Sig).    

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

%% ----------------------------------------------------------------------------
%% @spec  foldf(fun(), fun(), list()) -> term()
%% @doc Runs the first fun on elements in the list.
%%      Returns the first result for which the predicate is true
%% @end------------------------------------------------------------------------

foldf(F, Pred, [H|T]) ->
    Res = F(H),
    case Pred(Res) of
        true -> Res;
        _    -> foldf(F, Pred, T)
    end;
foldf(_,_,[]) -> false.
