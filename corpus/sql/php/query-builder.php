<?php
// The same report, with the query builder binding the value.
$name = request('name');
$rows = DB::table('users')->where('name', $name)->get();
foreach ($rows as $row) {
    echo e($row->name);
}
