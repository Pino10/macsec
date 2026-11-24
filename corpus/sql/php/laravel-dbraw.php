<?php
// A filter is pasted into a raw expression.
$name = $request->input('name');
$rows = DB::table('users')->select(DB::raw("id, name, '" . $name . "' AS searched"))->get(); // MACSEC-SQLI
return response()->json($rows);
