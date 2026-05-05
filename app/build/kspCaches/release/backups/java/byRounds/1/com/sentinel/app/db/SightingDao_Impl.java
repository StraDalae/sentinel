package com.sentinel.app.db;

import android.database.Cursor;
import android.os.CancellationSignal;
import androidx.annotation.NonNull;
import androidx.room.CoroutinesRoom;
import androidx.room.EntityDeletionOrUpdateAdapter;
import androidx.room.EntityInsertionAdapter;
import androidx.room.RoomDatabase;
import androidx.room.RoomSQLiteQuery;
import androidx.room.SharedSQLiteStatement;
import androidx.room.util.CursorUtil;
import androidx.room.util.DBUtil;
import androidx.sqlite.db.SupportSQLiteStatement;
import com.sentinel.app.model.DeviceSighting;
import java.lang.Class;
import java.lang.Exception;
import java.lang.Object;
import java.lang.Override;
import java.lang.String;
import java.lang.SuppressWarnings;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import javax.annotation.processing.Generated;
import kotlin.Unit;
import kotlin.coroutines.Continuation;

@Generated("androidx.room.RoomProcessor")
@SuppressWarnings({"unchecked", "deprecation"})
public final class SightingDao_Impl implements SightingDao {
  private final RoomDatabase __db;

  private final EntityInsertionAdapter<DeviceSighting> __insertionAdapterOfDeviceSighting;

  private final EntityDeletionOrUpdateAdapter<DeviceSighting> __updateAdapterOfDeviceSighting;

  private final SharedSQLiteStatement __preparedStmtOfDeleteOlderThan;

  private final SharedSQLiteStatement __preparedStmtOfClearAll;

  public SightingDao_Impl(@NonNull final RoomDatabase __db) {
    this.__db = __db;
    this.__insertionAdapterOfDeviceSighting = new EntityInsertionAdapter<DeviceSighting>(__db) {
      @Override
      @NonNull
      protected String createQuery() {
        return "INSERT OR REPLACE INTO `device_sightings` (`id`,`deviceFingerprint`,`rawMac`,`rssi`,`latitude`,`longitude`,`timestamp`,`seenAtLocations`,`threatScore`) VALUES (nullif(?, 0),?,?,?,?,?,?,?,?)";
      }

      @Override
      protected void bind(@NonNull final SupportSQLiteStatement statement,
          @NonNull final DeviceSighting entity) {
        statement.bindLong(1, entity.getId());
        statement.bindString(2, entity.getDeviceFingerprint());
        statement.bindString(3, entity.getRawMac());
        statement.bindLong(4, entity.getRssi());
        statement.bindDouble(5, entity.getLatitude());
        statement.bindDouble(6, entity.getLongitude());
        statement.bindLong(7, entity.getTimestamp());
        statement.bindLong(8, entity.getSeenAtLocations());
        statement.bindLong(9, entity.getThreatScore());
      }
    };
    this.__updateAdapterOfDeviceSighting = new EntityDeletionOrUpdateAdapter<DeviceSighting>(__db) {
      @Override
      @NonNull
      protected String createQuery() {
        return "UPDATE OR ABORT `device_sightings` SET `id` = ?,`deviceFingerprint` = ?,`rawMac` = ?,`rssi` = ?,`latitude` = ?,`longitude` = ?,`timestamp` = ?,`seenAtLocations` = ?,`threatScore` = ? WHERE `id` = ?";
      }

      @Override
      protected void bind(@NonNull final SupportSQLiteStatement statement,
          @NonNull final DeviceSighting entity) {
        statement.bindLong(1, entity.getId());
        statement.bindString(2, entity.getDeviceFingerprint());
        statement.bindString(3, entity.getRawMac());
        statement.bindLong(4, entity.getRssi());
        statement.bindDouble(5, entity.getLatitude());
        statement.bindDouble(6, entity.getLongitude());
        statement.bindLong(7, entity.getTimestamp());
        statement.bindLong(8, entity.getSeenAtLocations());
        statement.bindLong(9, entity.getThreatScore());
        statement.bindLong(10, entity.getId());
      }
    };
    this.__preparedStmtOfDeleteOlderThan = new SharedSQLiteStatement(__db) {
      @Override
      @NonNull
      public String createQuery() {
        final String _query = "DELETE FROM device_sightings WHERE timestamp < ?";
        return _query;
      }
    };
    this.__preparedStmtOfClearAll = new SharedSQLiteStatement(__db) {
      @Override
      @NonNull
      public String createQuery() {
        final String _query = "DELETE FROM device_sightings";
        return _query;
      }
    };
  }

  @Override
  public Object insert(final DeviceSighting sighting,
      final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        __db.beginTransaction();
        try {
          __insertionAdapterOfDeviceSighting.insert(sighting);
          __db.setTransactionSuccessful();
          return Unit.INSTANCE;
        } finally {
          __db.endTransaction();
        }
      }
    }, $completion);
  }

  @Override
  public Object update(final DeviceSighting sighting,
      final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        __db.beginTransaction();
        try {
          __updateAdapterOfDeviceSighting.handle(sighting);
          __db.setTransactionSuccessful();
          return Unit.INSTANCE;
        } finally {
          __db.endTransaction();
        }
      }
    }, $completion);
  }

  @Override
  public Object deleteOlderThan(final long before, final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        final SupportSQLiteStatement _stmt = __preparedStmtOfDeleteOlderThan.acquire();
        int _argIndex = 1;
        _stmt.bindLong(_argIndex, before);
        try {
          __db.beginTransaction();
          try {
            _stmt.executeUpdateDelete();
            __db.setTransactionSuccessful();
            return Unit.INSTANCE;
          } finally {
            __db.endTransaction();
          }
        } finally {
          __preparedStmtOfDeleteOlderThan.release(_stmt);
        }
      }
    }, $completion);
  }

  @Override
  public Object clearAll(final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        final SupportSQLiteStatement _stmt = __preparedStmtOfClearAll.acquire();
        try {
          __db.beginTransaction();
          try {
            _stmt.executeUpdateDelete();
            __db.setTransactionSuccessful();
            return Unit.INSTANCE;
          } finally {
            __db.endTransaction();
          }
        } finally {
          __preparedStmtOfClearAll.release(_stmt);
        }
      }
    }, $completion);
  }

  @Override
  public Object getRecentSightings(final long since,
      final Continuation<? super List<DeviceSighting>> $completion) {
    final String _sql = "SELECT * FROM device_sightings WHERE timestamp > ? ORDER BY timestamp DESC";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 1);
    int _argIndex = 1;
    _statement.bindLong(_argIndex, since);
    final CancellationSignal _cancellationSignal = DBUtil.createCancellationSignal();
    return CoroutinesRoom.execute(__db, false, _cancellationSignal, new Callable<List<DeviceSighting>>() {
      @Override
      @NonNull
      public List<DeviceSighting> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfId = CursorUtil.getColumnIndexOrThrow(_cursor, "id");
          final int _cursorIndexOfDeviceFingerprint = CursorUtil.getColumnIndexOrThrow(_cursor, "deviceFingerprint");
          final int _cursorIndexOfRawMac = CursorUtil.getColumnIndexOrThrow(_cursor, "rawMac");
          final int _cursorIndexOfRssi = CursorUtil.getColumnIndexOrThrow(_cursor, "rssi");
          final int _cursorIndexOfLatitude = CursorUtil.getColumnIndexOrThrow(_cursor, "latitude");
          final int _cursorIndexOfLongitude = CursorUtil.getColumnIndexOrThrow(_cursor, "longitude");
          final int _cursorIndexOfTimestamp = CursorUtil.getColumnIndexOrThrow(_cursor, "timestamp");
          final int _cursorIndexOfSeenAtLocations = CursorUtil.getColumnIndexOrThrow(_cursor, "seenAtLocations");
          final int _cursorIndexOfThreatScore = CursorUtil.getColumnIndexOrThrow(_cursor, "threatScore");
          final List<DeviceSighting> _result = new ArrayList<DeviceSighting>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final DeviceSighting _item;
            final long _tmpId;
            _tmpId = _cursor.getLong(_cursorIndexOfId);
            final String _tmpDeviceFingerprint;
            _tmpDeviceFingerprint = _cursor.getString(_cursorIndexOfDeviceFingerprint);
            final String _tmpRawMac;
            _tmpRawMac = _cursor.getString(_cursorIndexOfRawMac);
            final int _tmpRssi;
            _tmpRssi = _cursor.getInt(_cursorIndexOfRssi);
            final double _tmpLatitude;
            _tmpLatitude = _cursor.getDouble(_cursorIndexOfLatitude);
            final double _tmpLongitude;
            _tmpLongitude = _cursor.getDouble(_cursorIndexOfLongitude);
            final long _tmpTimestamp;
            _tmpTimestamp = _cursor.getLong(_cursorIndexOfTimestamp);
            final int _tmpSeenAtLocations;
            _tmpSeenAtLocations = _cursor.getInt(_cursorIndexOfSeenAtLocations);
            final int _tmpThreatScore;
            _tmpThreatScore = _cursor.getInt(_cursorIndexOfThreatScore);
            _item = new DeviceSighting(_tmpId,_tmpDeviceFingerprint,_tmpRawMac,_tmpRssi,_tmpLatitude,_tmpLongitude,_tmpTimestamp,_tmpSeenAtLocations,_tmpThreatScore);
            _result.add(_item);
          }
          return _result;
        } finally {
          _cursor.close();
          _statement.release();
        }
      }
    }, $completion);
  }

  @Override
  public Object getSightingsForDevice(final String fingerprint, final long since,
      final Continuation<? super List<DeviceSighting>> $completion) {
    final String _sql = "SELECT * FROM device_sightings WHERE deviceFingerprint = ? AND timestamp > ? ORDER BY timestamp ASC";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 2);
    int _argIndex = 1;
    _statement.bindString(_argIndex, fingerprint);
    _argIndex = 2;
    _statement.bindLong(_argIndex, since);
    final CancellationSignal _cancellationSignal = DBUtil.createCancellationSignal();
    return CoroutinesRoom.execute(__db, false, _cancellationSignal, new Callable<List<DeviceSighting>>() {
      @Override
      @NonNull
      public List<DeviceSighting> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfId = CursorUtil.getColumnIndexOrThrow(_cursor, "id");
          final int _cursorIndexOfDeviceFingerprint = CursorUtil.getColumnIndexOrThrow(_cursor, "deviceFingerprint");
          final int _cursorIndexOfRawMac = CursorUtil.getColumnIndexOrThrow(_cursor, "rawMac");
          final int _cursorIndexOfRssi = CursorUtil.getColumnIndexOrThrow(_cursor, "rssi");
          final int _cursorIndexOfLatitude = CursorUtil.getColumnIndexOrThrow(_cursor, "latitude");
          final int _cursorIndexOfLongitude = CursorUtil.getColumnIndexOrThrow(_cursor, "longitude");
          final int _cursorIndexOfTimestamp = CursorUtil.getColumnIndexOrThrow(_cursor, "timestamp");
          final int _cursorIndexOfSeenAtLocations = CursorUtil.getColumnIndexOrThrow(_cursor, "seenAtLocations");
          final int _cursorIndexOfThreatScore = CursorUtil.getColumnIndexOrThrow(_cursor, "threatScore");
          final List<DeviceSighting> _result = new ArrayList<DeviceSighting>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final DeviceSighting _item;
            final long _tmpId;
            _tmpId = _cursor.getLong(_cursorIndexOfId);
            final String _tmpDeviceFingerprint;
            _tmpDeviceFingerprint = _cursor.getString(_cursorIndexOfDeviceFingerprint);
            final String _tmpRawMac;
            _tmpRawMac = _cursor.getString(_cursorIndexOfRawMac);
            final int _tmpRssi;
            _tmpRssi = _cursor.getInt(_cursorIndexOfRssi);
            final double _tmpLatitude;
            _tmpLatitude = _cursor.getDouble(_cursorIndexOfLatitude);
            final double _tmpLongitude;
            _tmpLongitude = _cursor.getDouble(_cursorIndexOfLongitude);
            final long _tmpTimestamp;
            _tmpTimestamp = _cursor.getLong(_cursorIndexOfTimestamp);
            final int _tmpSeenAtLocations;
            _tmpSeenAtLocations = _cursor.getInt(_cursorIndexOfSeenAtLocations);
            final int _tmpThreatScore;
            _tmpThreatScore = _cursor.getInt(_cursorIndexOfThreatScore);
            _item = new DeviceSighting(_tmpId,_tmpDeviceFingerprint,_tmpRawMac,_tmpRssi,_tmpLatitude,_tmpLongitude,_tmpTimestamp,_tmpSeenAtLocations,_tmpThreatScore);
            _result.add(_item);
          }
          return _result;
        } finally {
          _cursor.close();
          _statement.release();
        }
      }
    }, $completion);
  }

  @Override
  public Object getThreats(final Continuation<? super List<DeviceSighting>> $completion) {
    final String _sql = "SELECT * FROM device_sightings WHERE seenAtLocations >= 3 ORDER BY seenAtLocations DESC";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 0);
    final CancellationSignal _cancellationSignal = DBUtil.createCancellationSignal();
    return CoroutinesRoom.execute(__db, false, _cancellationSignal, new Callable<List<DeviceSighting>>() {
      @Override
      @NonNull
      public List<DeviceSighting> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfId = CursorUtil.getColumnIndexOrThrow(_cursor, "id");
          final int _cursorIndexOfDeviceFingerprint = CursorUtil.getColumnIndexOrThrow(_cursor, "deviceFingerprint");
          final int _cursorIndexOfRawMac = CursorUtil.getColumnIndexOrThrow(_cursor, "rawMac");
          final int _cursorIndexOfRssi = CursorUtil.getColumnIndexOrThrow(_cursor, "rssi");
          final int _cursorIndexOfLatitude = CursorUtil.getColumnIndexOrThrow(_cursor, "latitude");
          final int _cursorIndexOfLongitude = CursorUtil.getColumnIndexOrThrow(_cursor, "longitude");
          final int _cursorIndexOfTimestamp = CursorUtil.getColumnIndexOrThrow(_cursor, "timestamp");
          final int _cursorIndexOfSeenAtLocations = CursorUtil.getColumnIndexOrThrow(_cursor, "seenAtLocations");
          final int _cursorIndexOfThreatScore = CursorUtil.getColumnIndexOrThrow(_cursor, "threatScore");
          final List<DeviceSighting> _result = new ArrayList<DeviceSighting>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final DeviceSighting _item;
            final long _tmpId;
            _tmpId = _cursor.getLong(_cursorIndexOfId);
            final String _tmpDeviceFingerprint;
            _tmpDeviceFingerprint = _cursor.getString(_cursorIndexOfDeviceFingerprint);
            final String _tmpRawMac;
            _tmpRawMac = _cursor.getString(_cursorIndexOfRawMac);
            final int _tmpRssi;
            _tmpRssi = _cursor.getInt(_cursorIndexOfRssi);
            final double _tmpLatitude;
            _tmpLatitude = _cursor.getDouble(_cursorIndexOfLatitude);
            final double _tmpLongitude;
            _tmpLongitude = _cursor.getDouble(_cursorIndexOfLongitude);
            final long _tmpTimestamp;
            _tmpTimestamp = _cursor.getLong(_cursorIndexOfTimestamp);
            final int _tmpSeenAtLocations;
            _tmpSeenAtLocations = _cursor.getInt(_cursorIndexOfSeenAtLocations);
            final int _tmpThreatScore;
            _tmpThreatScore = _cursor.getInt(_cursorIndexOfThreatScore);
            _item = new DeviceSighting(_tmpId,_tmpDeviceFingerprint,_tmpRawMac,_tmpRssi,_tmpLatitude,_tmpLongitude,_tmpTimestamp,_tmpSeenAtLocations,_tmpThreatScore);
            _result.add(_item);
          }
          return _result;
        } finally {
          _cursor.close();
          _statement.release();
        }
      }
    }, $completion);
  }

  @NonNull
  public static List<Class<?>> getRequiredConverters() {
    return Collections.emptyList();
  }
}
