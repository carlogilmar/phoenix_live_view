defmodule Phoenix.LiveView.Comprehension do
  @moduledoc """
  The struct returned by for-comprehensions in .leex templates.

  See a description about its fields and use cases
  in `Phoenix.LiveView.Engine` docs.
  """

  defstruct [:static, :dynamics]

  @type t :: %__MODULE__{
          static: [String.t()],
          dynamics: [[iodata()]]
        }

  defimpl Phoenix.HTML.Safe do
    def to_iodata(%Phoenix.LiveView.Comprehension{static: static, dynamics: dynamics}) do
      for dynamic <- dynamics, do: to_iodata(static, dynamic, [])
    end

    defp to_iodata([static_head | static_tail], [dynamic_head | dynamic_tail], acc) do
      to_iodata(static_tail, dynamic_tail, [dynamic_head, static_head | acc])
    end

    defp to_iodata([static_head], [], acc) do
      Enum.reverse([static_head | acc])
    end
  end
end

defmodule Phoenix.LiveView.Rendered do
  @moduledoc """
  The struct returned by .leex templates.

  See a description about its fields and use cases
  in `Phoenix.LiveView.Engine` docs.
  """

  defstruct [:static, :dynamic, :fingerprint]

  @type t :: %__MODULE__{
          static: [String.t()],
          dynamic: [
            nil | iodata() | Phoenix.LiveView.Rendered.t() | Phoenix.LiveView.Comprehension.t()
          ],
          fingerprint: integer()
        }

  defimpl Phoenix.HTML.Safe do
    def to_iodata(%Phoenix.LiveView.Rendered{static: static, dynamic: dynamic}) do
      to_iodata(static, dynamic, [])
    end

    def to_iodata(%Phoenix.LiveView.Comprehension{} = for) do
      Phoenix.HTML.Safe.Phoenix.LiveView.Comprehension.to_iodata(for)
    end

    def to_iodata(nil) do
      raise "cannot convert .leex template with change tracking to iodata"
    end

    def to_iodata(other) do
      other
    end

    defp to_iodata([static_head | static_tail], [dynamic_head | dynamic_tail], acc) do
      to_iodata(static_tail, dynamic_tail, [to_iodata(dynamic_head), static_head | acc])
    end

    defp to_iodata([static_head], [], acc) do
      Enum.reverse([static_head | acc])
    end
  end
end

defmodule Phoenix.LiveView.Engine do
  @behaviour Phoenix.Template.Engine
  @pdict_key {__MODULE__, :fingerprint}

  @impl true
  def compile(path, _name) do
    IO.puts "0 Iniciando..."
    compiled =EEx.compile_file(path, engine: __MODULE__, line: 1, trim: true)
    :finished
  end

  @behaviour EEx.Engine

  @impl true
  def init(_opts) do
    IO.puts "1... inicializando este pedo!!"
    %{
      static: [],
      dynamic: [],
      vars_count: 0
    }
  end

  @impl true
  def handle_begin(state) do
    IO.puts "... handle begin..."
    %{state | static: [], dynamic: []}
  end

  @impl true
  def handle_end(state) do
    IO.puts "3... handle end"
    %{static: static, dynamic: dynamic} = state
    safe = {:safe, Enum.reverse(static)}
    {:__block__, [], Enum.reverse([safe | dynamic])}
  end

  @impl true
  def handle_body(state) do
    IO.puts "2. ... handle body..."
    {fingerprint, entries} = to_rendered_struct(handle_end(state), true, false, %{}, %{})

    quote do
      require Phoenix.LiveView.Engine

      {fingerprint, __prints__} =
        Process.get(unquote(@pdict_key)) ||
          case var!(assigns) do
            %{socket: %{fingerprints: fingerprints}} -> fingerprints
            _ -> {nil, %{}}
          end

      __changed__ =
        case var!(assigns) do
          %{socket: %{changed: changed}} when unquote(fingerprint) == fingerprint -> changed
          _ -> nil
        end

      try do
        unquote({:__block__, [], entries})
      after
        Process.delete(unquote(@pdict_key))
      end
    end
  end

  @impl true
  def handle_text(state, text) do
    IO.puts "\n>> handle text!!!"
    IO.inspect state
    IO.inspect text
    IO.puts "<< handle text \n"
    %{static: static} = state
    %{state | static: [text | static]}
  end

  @impl true
  def handle_expr(state, "=", ast) do
    IO.puts "<< handle expression 1="
    IO.inspect state
    IO.inspect ast
    IO.puts ">> handle expression 1= \n"
    %{static: static, dynamic: dynamic, vars_count: vars_count} = state
    var = Macro.var(:"arg#{vars_count}", __MODULE__)
    ast = quote do: unquote(var) = unquote(__MODULE__).to_safe(unquote(ast))
    %{state | dynamic: [ast | dynamic], static: [var | static], vars_count: vars_count + 1}
  end

  def handle_expr(state, "", ast) do
    IO.puts "handle_expression 2-"
    %{dynamic: dynamic} = state
    %{state | dynamic: [ast | dynamic]}
  end

  def handle_expr(state, marker, ast) do
    IO.inspect "handle_expr 3marker"
    EEx.Engine.handle_expr(state, marker, ast)
  end

  ## Emit conditional variables for dirty assigns tracking.

  defp maybe_pdict_fingerprint(ast, false, _counter), do: ast

  defp maybe_pdict_fingerprint(ast, true, counter) do
    quote do
      case __prints__ do
        %{unquote(counter) => {_, _} = print} -> Process.put(unquote(@pdict_key), print)
        %{} -> :ok
      end

      unquote(ast)
    end
  end

  defp to_conditional_var(:all, var, live_struct) do
    quote do: unquote(var) = unquote(live_struct)
  end

  defp to_conditional_var([], var, live_struct) do
    quote do
      unquote(var) =
        case __changed__ do
          %{} -> nil
          _ -> unquote(live_struct)
        end
    end
  end

  defp to_conditional_var(keys, var, live_struct) do
    quote do
      unquote(var) =
        case unquote(changed_assigns(keys)) do
          true -> unquote(live_struct)
          false -> nil
        end
    end
  end

  defp changed_assigns(assigns) do
    assigns
    |> Enum.map(fn assign ->
      quote do: unquote(__MODULE__).changed_assign?(__changed__, unquote(assign))
    end)
    |> Enum.reduce(&{:or, [], [&1, &2]})
  end

  ## Optimize possible expressions into live structs (rendered / comprehensions)

  defp to_live_struct(
         {:if, meta, [condition, [{:do, do_block} | opts]]},
         tainted_vars,
         vars,
         assigns
       ) do
    {condition, tainted_vars, vars, assigns} = analyze(condition, tainted_vars, vars, assigns)
    do_block = maybe_block_to_rendered(do_block, tainted_vars, vars, assigns)
    # It is ok to convert else to an empty string as to_safe would do it anyway.
    else_block =
      maybe_block_to_rendered(Keyword.get(opts, :else, ""), tainted_vars, vars, assigns)

    to_safe({:if, meta, [condition, [do: do_block, else: else_block]]}, true)
  end

  defp to_live_struct({:for, meta, args} = expr, _tainted_vars, _vars, _assigns) do
    with {filters, [[do: {:__block__, _, block}]]} <- Enum.split(args, -1),
         {exprs, [{:safe, iodata}]} <- Enum.split(block, -1) do
      {binaries, vars} = bins_and_vars(iodata)
      for = {:for, meta, filters ++ [[do: {:__block__, [], exprs ++ [vars]}]]}

      quote do
        for = unquote(for)
        %Phoenix.LiveView.Comprehension{static: unquote(binaries), dynamics: for}
      end
    else
      _ -> to_safe(expr, true)
    end
  end

  defp to_live_struct(expr, _tainted_vars, _vars, _assigns) do
    to_safe(expr, true)
  end

  defp maybe_block_to_rendered(block, tainted_vars, vars, assigns) do
    case to_rendered_struct(block, false, tainted_vars, vars, assigns) do
      {_fingerprint, rendered} -> {:__block__, [], rendered}
      :error -> block
    end
  end

  defp to_rendered_struct(expr, check_prints?, tainted_vars, vars, assigns) do
    with {:__block__, _, entries} <- expr,
         {dynamic, [{:safe, static}]} <- Enum.split(entries, -1) do
      {block, _} =
        Enum.map_reduce(dynamic, {0, vars}, fn
          {:=, [], [{_, _, __MODULE__} = var, {{:., _, [__MODULE__, :to_safe]}, _, [ast]}]},
          {counter, vars} ->
            {ast, keys, vars} = analyze_and_return_tainted_keys(ast, tainted_vars, vars, assigns)
            live_struct = to_live_struct(ast, tainted_vars, vars, assigns)
            fingerprint_live_struct = maybe_pdict_fingerprint(live_struct, check_prints?, counter)
            {to_conditional_var(keys, var, fingerprint_live_struct), {counter + 1, vars}}

          ast, {counter, vars} ->
            {ast, _, vars, _} = analyze(ast, tainted_vars, vars, assigns)
            {ast, {counter, vars}}
        end)

      {static, dynamic} = bins_and_vars(static)

      # We compute the term to binary instead of passing all binaries
      # because we need to take into account the positions of dynamics.
      <<fingerprint::8*16>> =
        static
        |> :erlang.term_to_binary()
        |> :erlang.md5()

      rendered =
        quote do
          %Phoenix.LiveView.Rendered{
            static: unquote(static),
            dynamic: unquote(dynamic),
            fingerprint: unquote(fingerprint)
          }
        end

      {fingerprint, block ++ [rendered]}
    else
      _ -> :error
    end
  end

  ## Extracts binaries and variable from iodata

  defp bins_and_vars(acc),
    do: bins_and_vars(acc, [], [])

  defp bins_and_vars([bin1, bin2 | acc], bins, vars) when is_binary(bin1) and is_binary(bin2),
    do: bins_and_vars([bin1 <> bin2 | acc], bins, vars)

  defp bins_and_vars([bin, var | acc], bins, vars) when is_binary(bin) and is_tuple(var),
    do: bins_and_vars(acc, [bin | bins], [var | vars])

  defp bins_and_vars([var | acc], bins, vars) when is_tuple(var),
    do: bins_and_vars(acc, ["" | bins], [var | vars])

  defp bins_and_vars([bin], bins, vars) when is_binary(bin),
    do: {Enum.reverse([bin | bins]), Enum.reverse(vars)}

  defp bins_and_vars([], bins, vars),
    do: {Enum.reverse(["" | bins]), Enum.reverse(vars)}

  ## Assigns tracking

  @lexical_forms [:import, :alias, :require]

  # Here we compute if an expression should be always computed (:tainted),
  # never computed (no assigns) or some times computed based on assigns.
  #
  # If any assign is used, we store it in the assigns and use it to compute
  # if it should be changed or not.
  #
  # However, operations that change the lexical scope, such as imports and
  # defining variables, taint the analysis. Because variables can be set at
  # any moment in Elixir, via macros, without appearing on the left side of
  # `=` or in a clause, whenever we see a variable, we consider it as tainted,
  # regardless of its position.
  #
  # The tainting that happens from lexical scope is called weak-tainting,
  # because it is disabled under certain special forms. There is also
  # strong-tainting, which are always computed. Strong-tainting only happens
  # if the `assigns` variable is used.
  defp analyze_and_return_tainted_keys(ast, tainted_vars, vars, assigns) do
    {ast, tainted_vars, vars, assigns} = analyze(ast, tainted_vars, vars, assigns)
    {tainted_assigns?, assigns} = Map.pop(assigns, __MODULE__, false)
    keys = if tainted_vars or tainted_assigns?, do: :all, else: Map.keys(assigns)
    {ast, keys, vars}
  end

  # Non-expanded assign access
  defp analyze({:@, meta, [{name, _, context}]}, tainted_vars, vars, assigns)
       when is_atom(name) and is_atom(context) do
    assigns_var = Macro.var(:assigns, nil)

    expr =
      quote line: meta[:line] || 0 do
        unquote(__MODULE__).fetch_assign!(unquote(assigns_var), unquote(name))
      end

    {expr, tainted_vars, vars, Map.put(assigns, name, true)}
  end

  # Expanded assign access. The non-expanded form is handled on root,
  # then all further traversals happen on the expanded form
  defp analyze(
         {{:., _, [__MODULE__, :fetch_assign!]}, _, [{:assigns, _, nil}, name]} = expr,
         tainted_vars,
         vars,
         assigns
       )
       when is_atom(name) do
    {expr, tainted_vars, vars, Map.put(assigns, name, true)}
  end

  # Assigns is a strong-taint
  defp analyze({:assigns, _, nil} = expr, tainted_vars, vars, assigns) do
    {expr, tainted_vars, vars, taint(assigns)}
  end

  # Our own vars are ignored. They appear from nested do/end in EEx templates.
  defp analyze({_, _, __MODULE__} = expr, tainted_vars, vars, assigns) do
    {expr, tainted_vars, vars, assigns}
  end

  # Vars always taint
  defp analyze({name, _, context} = expr, tainted_vars, vars, assigns)
       when is_atom(name) and is_atom(context) do
    if tainted_vars == :restricted do
      {expr, Map.has_key?(vars, {name, context}) || :restricted, vars, assigns}
    else
      {expr, true, Map.put(vars, {name, context}, true), assigns}
    end
  end

  # Lexical forms always taint
  defp analyze({lexical_form, _, [_]} = expr, tainted_vars, vars, assigns)
       when lexical_form in @lexical_forms do
    tainted_vars = if tainted_vars == :restricted, do: :restricted, else: true
    {expr, tainted_vars, vars, assigns}
  end

  defp analyze({lexical_form, _, [_, _]} = expr, tainted_vars, vars, assigns)
       when lexical_form in @lexical_forms do
    tainted_vars = if tainted_vars == :restricted, do: :restricted, else: true
    {expr, tainted_vars, vars, assigns}
  end

  # with/for/fn never taint regardless of arity
  defp analyze({special_form, meta, args}, tainted_vars, vars, assigns)
       when special_form in [:with, :for, :fn] do
    {args, tainted_vars, vars, assigns} =
      analyze_with_restricted_tainted_vars(args, tainted_vars, vars, assigns)

    {{special_form, meta, args}, tainted_vars, vars, assigns}
  end

  # case/2 only taint first arg
  defp analyze({:case, meta, [expr, blocks]}, tainted_vars, vars, assigns) do
    {expr, tainted_vars, vars, assigns} = analyze(expr, tainted_vars, vars, assigns)

    {blocks, tainted_vars, vars, assigns} =
      analyze_with_restricted_tainted_vars(blocks, tainted_vars, vars, assigns)

    {{:case, meta, [expr, blocks]}, tainted_vars, vars, assigns}
  end

  # try/receive/cond/&/1 never taint
  defp analyze({special_form, meta, [blocks]}, tainted_vars, vars, assigns)
       when special_form in [:try, :receive, :cond, :&] do
    {blocks, tainted_vars, vars, assigns} =
      analyze_with_restricted_tainted_vars(blocks, tainted_vars, vars, assigns)

    {{special_form, meta, [blocks]}, tainted_vars, vars, assigns}
  end

  defp analyze({left, meta, args}, tainted_vars, vars, assigns) do
    {left, tainted_vars, vars, assigns} = analyze(left, tainted_vars, vars, assigns)
    {args, tainted_vars, vars, assigns} = analyze_list(args, tainted_vars, vars, assigns, [])
    {{left, meta, args}, tainted_vars, vars, assigns}
  end

  defp analyze({left, right}, tainted_vars, vars, assigns) do
    {left, tainted_vars, vars, assigns} = analyze(left, tainted_vars, vars, assigns)
    {right, tainted_vars, vars, assigns} = analyze(right, tainted_vars, vars, assigns)
    {{left, right}, tainted_vars, vars, assigns}
  end

  defp analyze([_ | _] = list, tainted_vars, vars, assigns) do
    analyze_list(list, tainted_vars, vars, assigns, [])
  end

  defp analyze(other, tainted_vars, vars, assigns) do
    {other, tainted_vars, vars, assigns}
  end

  defp analyze_list([head | tail], tainted_vars, vars, assigns, acc) do
    {head, tainted_vars, vars, assigns} = analyze(head, tainted_vars, vars, assigns)
    analyze_list(tail, tainted_vars, vars, assigns, [head | acc])
  end

  defp analyze_list([], tainted_vars, vars, assigns, acc) do
    {Enum.reverse(acc), tainted_vars, vars, assigns}
  end

  # tainted_vars is mostly a boolean. False means variables are not
  # tainted, true means they are. Seeing a variable at any moment
  # taints it.
  #
  # However, for case/cond/with/fn/try, the variable is only tainted
  # if it came from outside of the case/cond/with/fn/try. So for those
  # constructs we set the mode to restricted and stop collecting vars.
  defp analyze_with_restricted_tainted_vars(ast, tainted_vars, vars, assigns) do
    {analyzed, tainted_vars, _vars, assigns} =
      analyze(ast, tainted_vars || :restricted, vars, assigns)

    {analyzed, tainted_vars == true, vars, assigns}
  end

  defp taint(assigns) do
    Map.put(assigns, __MODULE__, true)
  end

  ## Callbacks

  @doc false
  defmacro to_safe(ast) do
    to_safe(ast, false)
  end

  defp to_safe(ast, rendered_catch_all?) do
    line = line_from_expr(ast)

    extra_clauses =
      if rendered_catch_all? do
        quote generated: true, line: line do
          %{__struct__: Phoenix.LiveView.Rendered} = other -> other
        end
      else
        []
      end

    to_safe(ast, line, extra_clauses)
  end

  defp line_from_expr({_, meta, _}) when is_list(meta), do: Keyword.get(meta, :line)
  defp line_from_expr(_), do: nil

  # We can do the work at compile time
  defp to_safe(literal, _line, _extra_clauses)
       when is_binary(literal) or is_atom(literal) or is_number(literal) do
    Phoenix.HTML.Safe.to_iodata(literal)
  end

  # We can do the work at runtime
  defp to_safe(literal, line, _extra_clauses) when is_list(literal) do
    quote line: line, do: Phoenix.HTML.Safe.List.to_iodata(unquote(literal))
  end

  defp to_safe(expr, line, extra_clauses) do
    # Keep stacktraces for protocol dispatch and coverage
    safe_return = quote line: line, do: data
    bin_return = quote line: line, do: Plug.HTML.html_escape_to_iodata(bin)
    other_return = quote line: line, do: Phoenix.HTML.Safe.to_iodata(other)

    # However ignore them for the generated clauses to avoid warnings
    clauses =
      quote generated: true do
        {:safe, data} -> unquote(safe_return)
        bin when is_binary(bin) -> unquote(bin_return)
        other -> unquote(other_return)
      end

    quote generated: true do
      case unquote(expr), do: unquote(extra_clauses ++ clauses)
    end
  end

  @doc false
  def changed_assign?(nil, _name) do
    true
  end

  def changed_assign?(changed, name) do
    case changed do
      %{^name => _} -> true
      %{} -> false
    end
  end

  @doc false
  def fetch_assign!(assigns, key) do
    case assigns do
      %{^key => val} ->
        val

      %{} ->
        raise ArgumentError, """
        assign @#{key} not available in eex template.

        Please make sure all proper assigns have been set. If this
        is a child template, ensure assigns are given explicitly by
        the parent template as they are not automatically forwarded.

        Available assigns: #{inspect(Enum.map(assigns, &elem(&1, 0)))}
        """
    end
  end
end
