<?php
// The filter is a bound value, not an expression.
$name = $request->input('name');
$rows = DB::table('users')->select('id', 'name')->where('name', $name)->get();
return response()->json($rows);
