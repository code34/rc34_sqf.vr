	/*
	RC34_SQF a translation of OO_CIPHER
	Copyright (c) 2018 Nicolas BOITEUX

	MIT License
	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.*/

	// Transform Decimal to Binary
	RC34_DecToBin= {
		private _binary = [];
		private _decimal = 0;
		private _bool = false;
		private _power = 0;

		{
			if (_x > 255) then {_decimal = 0;} else {_decimal = _x;};
			for "_i" from 7 to 0 step -1 do {
				_power = 2^(_i);
				_bool = (_power <= _decimal);
				_binary pushBack _bool;
				if (_bool) then {_decimal = _decimal - _power};
			};
		} count _this;
		_binary;
	};

	// Transform Binary to Decimal
	RC34_BinToDec = {
		private _decimal = 0;
		private _decimals = [];
		private _bool = false;
		private _power = 0;

		while { count _this > 0} do {
			_decimal = 0;
			for "_i" from 7 to 0 step -1 do {
				_bool = _this deleteat 0;
				_power = 2^(_i);
				if(_bool) then {_decimal = _decimal + _power; };
			};
			if(_decimal isEqualTo 0) then { _decimal = 256;};
			_decimals pushBack _decimal;
		};
		_decimals;
	};

	// Transform Decimal to Hexa
	RC34_DecToHexa = {
		private _hexa = "0123456789abcdef";
		private _strings = "";

		{
			if(_x isEqualTo 256) then {_x = 0;};
			{
				_strings = _strings + (_hexa select [_x,1]);
			}foreach [floor (_x / 16), (_x mod 16)];
		} forEach _this;
		_strings;
	};

	// Transform String to Hexa
	RC34_StrToHexa = {
			(toArray (_this)) call RC34_DecToHexa;
	};

	// Transform Hexa to Decimal
	RC34_HexaToDec = {
		private _hexa = toArray "0123456789abcdef";
		private _array = toArray _this;
		private _decimals = [];
		private _decimal = 0;

		while { count _array > 0 } do {
			_decimal = (_hexa find (_array select 0)) * 16 + (_hexa find (_array select 1));
			if(_decimal isEqualTo 0) then {_decimal = 256;};
			_decimals pushBack _decimal;
			_array deleteRange [0,2];
		};
		_decimals;
	};

	// Generate key
	RC34_KeySchedule = {
		private _key = _this;
		private _keylen = 256;
		private _array = [];
		private _j = 0;
		private _permute = 0;
		private _index1 = 0;
		private _index2 = 0;

		while { count _key < _keylen} do { _key pushBack 1; };

		for "_i" from 0 to 255 step 1 do { _array set [_i, _i]; };
		for "_i" from 0 to 255 step 1 do {
			_permute = (_array select _i);
			_j = (_j + _permute + (_key select _i)) mod 256;
			_array set [_i, (_array select _j)];
			_array set [_j, _permute];
		};
		_array;
	};

	RC34_Cipher = {
		if!((_this select 0) isEqualType "") exitWith { hintC "RC34::error: key must be a string"; "";};
		if!((_this select 1) isEqualType "") exitWith { hintC "RC34::error: data must be a string"; "";};
		(_this call RC34_Crypt) call RC34_DecToHexa;
	};

	RC34_Uncipher = {
		if!((_this select 0) isEqualType "") exitWith { hintC "RC34::error: key must be a string"; "";};
		if!((_this select 1) isEqualType "") exitWith { hintC "RC34::error: data must be an hexa string"; "";};
		private _array = [_this select 0, (_this select 1) call RC34_HexaToDec];
		toString(_array call RC34_Crypt);
	};

	RC34_Crypt = {
		private _data = [];
		if((_this select 1) isEqualType "") then { _data = toArray (_this select 1); } else { _data = _this select 1;};
		private _i = 0;
		private _j = 0;
		private _key = (toArray (_this select 0)) call RC34_KeySchedule;
		private _permute = 0;
		private _keystream = [];
		private _cipherdata = [];

		{
			_i = (_i + 1) mod 256; // 1
			_j = (_j + (_key select _i)) mod 256; // 32
			_permute = (_key select _i);
			_key set [_i, (_key select _j)];
			_key set [_j, _permute];
			_keystream pushBack (_key select (((_key select _i) + (_key select _j)) mod 256));
			true;
		} count _data;

		_data = _data call RC34_DecToBin;
		{
			_cipherdata pushBack ((_x || _data select _forEachIndex) && !(_x && _data select _forEachIndex));
		} forEach (_keystream call RC34_DecToBin);
		_cipherdata call RC34_BinToDec;
	};