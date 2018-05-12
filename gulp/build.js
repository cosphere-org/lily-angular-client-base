const gulp = require('gulp');
const tsc = require('gulp-typescript');
const tslint = require('gulp-tslint');
const tslintReporter = require('gulp-tslint-jenkins-reporter');
const runSequence = require('run-sequence');

const tsProject = tsc.createProject('tsconfig.json');

gulp.task('build', function () {
  runSequence(
    'compile-ts'
  );
});

gulp.task('compile-ts', function () {
  return gulp.src('src/**/*.ts')
    .pipe(tsProject())
    .pipe(gulp.dest('dist'));
});

gulp.task('watch', function() {
  gulp.watch('src/**/*.ts', ['build']);
});

gulp.task('tslint', function() {
  return gulp.src('./src/**/*.ts')
    .pipe(tslint())
    .pipe(tslintReporter({
      filename: './logs/checkstyle-tslint.xml'
    }));
});
